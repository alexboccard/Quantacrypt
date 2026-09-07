"""Tests for QuantaCrypt encrypted volume (.qcv) feature."""

import base64
import errno
import hashlib
import json
import os
import struct
import sys
import tempfile

import pytest

from quantacrypt.core import crypto as cc
from quantacrypt.core import volume as vol


# ── Header tests ────────────────────────────────────────────────────────────

class TestVolumeHeader:

    def test_write_and_read_header(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.qcv")
        vid = os.urandom(16)
        mn = os.urandom(12)
        dn = os.urandom(12)

        with open(path, "wb") as f:
            vol.write_header(f, vid, mn, dn)
            # Pad to make a valid file
            f.write(b"\x00" * 100)

        with open(path, "rb") as f:
            h = vol.read_header(f)

        assert h["version"] == vol.VOLUME_FORMAT_VERSION
        assert h["volume_id"] == vid
        assert h["meta_nonce"] == mn
        assert h["dir_nonce"] == dn

    def test_bad_magic_raises(self, tmp_dir):
        path = os.path.join(tmp_dir, "bad.qcv")
        with open(path, "wb") as f:
            f.write(b"\x00" * vol.HEADER_SIZE)

        with open(path, "rb") as f:
            with pytest.raises(ValueError, match="bad magic"):
                vol.read_header(f)

    def test_too_small_raises(self, tmp_dir):
        path = os.path.join(tmp_dir, "tiny.qcv")
        with open(path, "wb") as f:
            f.write(b"QCVOL\x01")  # only 6 bytes

        with open(path, "rb") as f:
            with pytest.raises(ValueError, match="too small"):
                vol.read_header(f)

    def test_unsupported_version_raises(self, tmp_dir):
        path = os.path.join(tmp_dir, "future.qcv")
        header = bytearray(vol.HEADER_SIZE)
        header[0:6] = vol.VOLUME_MAGIC
        struct.pack_into(">I", header, 6, 999)  # future version
        with open(path, "wb") as f:
            f.write(bytes(header))

        with open(path, "rb") as f:
            with pytest.raises(ValueError, match="Unsupported volume format"):
                vol.read_header(f)


# ── Encrypted block tests ──────────────────────────────────────────────────

class TestEncryptedBlocks:

    def test_write_read_roundtrip(self, tmp_dir):
        path = os.path.join(tmp_dir, "block.bin")
        data = os.urandom(1024)
        with open(path, "wb") as f:
            written = vol._write_encrypted_block(f, data)
        assert written == 4 + len(data)

        with open(path, "rb") as f:
            result = vol._read_encrypted_block(f)
        assert result == data

    def test_read_truncated_length(self, tmp_dir):
        path = os.path.join(tmp_dir, "trunc.bin")
        with open(path, "wb") as f:
            f.write(b"\x00\x00")  # only 2 bytes instead of 4

        with open(path, "rb") as f:
            with pytest.raises(ValueError, match="block length"):
                vol._read_encrypted_block(f)

    def test_read_truncated_data(self, tmp_dir):
        path = os.path.join(tmp_dir, "trunc2.bin")
        with open(path, "wb") as f:
            f.write(struct.pack(">I", 1000))  # claims 1000 bytes
            f.write(b"\x00" * 10)  # only 10

        with open(path, "rb") as f:
            with pytest.raises(ValueError, match="block data"):
                vol._read_encrypted_block(f)


# ── Metadata encryption ────────────────────────────────────────────────────

class TestMetadataEncryption:

    def test_roundtrip(self):
        key = os.urandom(64)
        meta = {"mode": "single", "version": 1, "chunk_size": 65536}
        nonce, ct = vol.encrypt_metadata(key, meta)
        result = vol.decrypt_metadata(key, nonce, ct)
        assert result == meta

    def test_wrong_key_fails(self):
        key1 = os.urandom(64)
        key2 = os.urandom(64)
        meta = {"test": "data"}
        nonce, ct = vol.encrypt_metadata(key1, meta)
        with pytest.raises(Exception):
            vol.decrypt_metadata(key2, nonce, ct)

    def test_tampered_ct_fails(self):
        key = os.urandom(64)
        meta = {"test": "data"}
        nonce, ct = vol.encrypt_metadata(key, meta)
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(Exception):
            vol.decrypt_metadata(key, nonce, bytes(tampered))


# ── Directory index encryption ──────────────────────────────────────────────

class TestDirectoryEncryption:

    def test_roundtrip(self):
        key = os.urandom(64)
        dir_index = {
            "/hello.txt": {"type": "file", "size": 100, "mode": 0o100644},
            "/subdir/": {"type": "dir", "mode": 0o40755},
        }
        nonce, ct = vol.encrypt_directory(key, dir_index)
        result = vol.decrypt_directory(key, nonce, ct)
        assert result == dir_index

    def test_empty_directory(self):
        key = os.urandom(64)
        nonce, ct = vol.encrypt_directory(key, {})
        result = vol.decrypt_directory(key, nonce, ct)
        assert result == {}

    def test_nested_structure(self):
        key = os.urandom(64)
        deep = {
            "/a/b/c/d.txt": {"type": "file", "size": 1},
            "/a/b/c/": {"type": "dir", "mode": 0o40755},
            "/a/b/": {"type": "dir", "mode": 0o40755},
            "/a/": {"type": "dir", "mode": 0o40755},
        }
        nonce, ct = vol.encrypt_directory(key, deep)
        result = vol.decrypt_directory(key, nonce, ct)
        assert result == deep


# ── File data encryption ────────────────────────────────────────────────────

class TestFileDataEncryption:

    def test_roundtrip_small_file(self):
        key = os.urandom(64)
        data = b"Hello, encrypted volume!"
        nonce, blob, count, sha = vol.encrypt_file_data(data, key)
        assert count == 1
        assert sha == hashlib.sha256(data).hexdigest()
        result = vol.decrypt_file_data(blob, key, nonce, count)
        assert result == data

    def test_roundtrip_empty_file(self):
        key = os.urandom(64)
        data = b""
        nonce, blob, count, sha = vol.encrypt_file_data(data, key)
        assert count == 1
        assert sha == hashlib.sha256(b"").hexdigest()
        result = vol.decrypt_file_data(blob, key, nonce, count)
        assert result == data

    def test_roundtrip_multi_chunk(self):
        key = os.urandom(64)
        # Make data larger than VOLUME_CHUNK_SIZE (64 KB)
        data = os.urandom(vol.VOLUME_CHUNK_SIZE * 3 + 1234)
        nonce, blob, count, sha = vol.encrypt_file_data(data, key)
        assert count == 4  # 3 full chunks + 1 partial
        assert sha == hashlib.sha256(data).hexdigest()
        result = vol.decrypt_file_data(blob, key, nonce, count)
        assert result == data

    def test_roundtrip_exact_chunk_boundary(self):
        key = os.urandom(64)
        data = os.urandom(vol.VOLUME_CHUNK_SIZE * 2)
        nonce, blob, count, sha = vol.encrypt_file_data(data, key)
        assert count == 2
        result = vol.decrypt_file_data(blob, key, nonce, count)
        assert result == data

    def test_wrong_key_fails(self):
        key1 = os.urandom(64)
        key2 = os.urandom(64)
        data = b"secret data"
        nonce, blob, count, _ = vol.encrypt_file_data(data, key1)
        with pytest.raises(ValueError, match="Authentication failed"):
            vol.decrypt_file_data(blob, key2, nonce, count)

    def test_tampered_blob_fails(self):
        key = os.urandom(64)
        data = b"secret data"
        nonce, blob, count, _ = vol.encrypt_file_data(data, key)
        tampered = bytearray(blob)
        tampered[12] ^= 0xFF
        with pytest.raises(ValueError):
            vol.decrypt_file_data(bytes(tampered), key, nonce, count)

    def test_truncated_blob_fails(self):
        key = os.urandom(64)
        data = b"test data"
        nonce, blob, count, _ = vol.encrypt_file_data(data, key)
        # Truncate to just the header of first chunk
        with pytest.raises(ValueError, match="truncated"):
            vol.decrypt_file_data(blob[:6], key, nonce, count)

    def test_truncated_header_fails(self):
        key = os.urandom(64)
        data = b"test data"
        nonce, blob, count, _ = vol.encrypt_file_data(data, key)
        with pytest.raises(ValueError, match="truncated"):
            vol.decrypt_file_data(blob[:4], key, nonce, count)

    def test_custom_chunk_size(self):
        key = os.urandom(64)
        data = os.urandom(500)
        nonce, blob, count, sha = vol.encrypt_file_data(data, key, chunk_size=100)
        assert count == 5
        result = vol.decrypt_file_data(blob, key, nonce, count)
        assert result == data


# ── Volume creation (password mode) ────────────────────────────────────────

class TestCreateVolumeSingle:

    def test_create_and_open(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.qcv")
        password = "test-password-123"

        progress = []
        meta = vol.create_volume_single(path, password, progress_cb=progress.append)

        assert meta["mode"] == "single"
        assert meta["format_version"] == vol.VOLUME_FORMAT_VERSION
        assert os.path.isfile(path)
        assert len(progress) > 0

        # Derive key and open
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        assert vc.dir_index == {}
        assert vc.metadata["mode"] == "single"

    def test_wrong_password_fails(self, tmp_dir):
        path = os.path.join(tmp_dir, "test.qcv")
        meta = vol.create_volume_single(path, "correct-testpad")

        with pytest.raises(Exception):
            vol.derive_volume_key_single("wrong", meta)


# ── Volume creation (Shamir mode) ──────────────────────────────────────────

class TestCreateVolumeShamir:

    def test_create_and_open(self, tmp_dir):
        path = os.path.join(tmp_dir, "shamir.qcv")
        progress = []
        meta, shares = vol.create_volume_shamir(path, n=3, k=2,
                                                 progress_cb=progress.append)

        assert meta["mode"] == "shamir"
        assert meta["threshold"] == 2
        assert meta["total"] == 3
        assert len(shares) == 3
        assert len(progress) > 0

        # Open with threshold shares
        final_key = vol.derive_volume_key_shamir(shares[:2], meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        assert vc.dir_index == {}

    def test_any_k_of_n_shares_work(self, tmp_dir):
        path = os.path.join(tmp_dir, "shamir.qcv")
        meta, shares = vol.create_volume_shamir(path, n=5, k=3)

        # Try shares 0,1,2
        key1 = vol.derive_volume_key_shamir(shares[:3], meta)
        # Try shares 2,3,4
        key2 = vol.derive_volume_key_shamir(shares[2:5], meta)
        assert key1 == key2

    def test_insufficient_shares_fail(self, tmp_dir):
        path = os.path.join(tmp_dir, "shamir.qcv")
        meta, shares = vol.create_volume_shamir(path, n=3, k=2)

        with pytest.raises(Exception):
            # Only 1 share when 2 needed — recovery gives wrong key
            key = vol.derive_volume_key_shamir(shares[:1], meta)
            vc = vol.VolumeContainer(path, key)
            vc.open()  # should fail on decrypt


# ── VolumeContainer operations ──────────────────────────────────────────────

class TestVolumeContainer:

    @pytest.fixture
    def open_volume(self, tmp_dir):
        """Create and return an open VolumeContainer."""
        path = os.path.join(tmp_dir, "vol.qcv")
        password = "testpw-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        return vc

    def test_write_and_read_file(self, open_volume):
        vc = open_volume
        data = b"Hello, volume!"
        vc.write_file("/hello.txt", data)
        assert vc.read_file("/hello.txt") == data

    def test_write_and_persist(self, open_volume, tmp_dir):
        vc = open_volume
        vc.write_file("/persist.txt", b"persisted data")
        vc.save()

        # Reopen from disk
        password = "testpw-testpad"
        meta = vc.metadata
        final_key = vol.derive_volume_key_single(password, meta)
        vc2 = vol.VolumeContainer(vc.path, final_key)
        vc2.open()
        assert vc2.read_file("/persist.txt") == b"persisted data"

    def test_list_dir_root(self, open_volume):
        vc = open_volume
        vc.write_file("/a.txt", b"a")
        vc.write_file("/b.txt", b"b")
        vc.mkdir("/subdir")
        entries = vc.list_dir("/")
        assert "a.txt" in entries
        assert "b.txt" in entries
        assert "subdir" in entries

    def test_list_dir_subdirectory(self, open_volume):
        vc = open_volume
        vc.mkdir("/docs")
        vc.write_file("/docs/readme.md", b"# Hello")
        vc.write_file("/docs/notes.txt", b"notes")
        entries = vc.list_dir("/docs")
        assert sorted(entries) == ["notes.txt", "readme.md"]

    def test_mkdir_idempotent(self, open_volume):
        vc = open_volume
        vc.mkdir("/test")
        vc.mkdir("/test")  # should not raise

    def test_delete_file(self, open_volume):
        vc = open_volume
        vc.write_file("/delete-me.txt", b"bye")
        assert vc.get_entry("/delete-me.txt") is not None
        vc.delete("/delete-me.txt")
        assert vc.get_entry("/delete-me.txt") is None

    def test_delete_nonexistent_raises(self, open_volume):
        with pytest.raises(FileNotFoundError):
            open_volume.delete("/nope.txt")

    def test_delete_nonempty_dir_raises(self, open_volume):
        vc = open_volume
        vc.mkdir("/stuff")
        vc.write_file("/stuff/file.txt", b"data")
        with pytest.raises(OSError, match="not empty"):
            vc.delete("/stuff/")

    def test_delete_empty_dir(self, open_volume):
        vc = open_volume
        vc.mkdir("/empty")
        vc.delete("/empty/")
        assert vc.get_entry("/empty/") is None

    def test_rename_file(self, open_volume):
        vc = open_volume
        vc.write_file("/old.txt", b"data")
        vc.rename("/old.txt", "/new.txt")
        assert vc.get_entry("/old.txt") is None
        assert vc.get_entry("/new.txt") is not None
        assert vc.read_file("/new.txt") == b"data"

    def test_rename_nonexistent_raises(self, open_volume):
        with pytest.raises(FileNotFoundError):
            open_volume.rename("/nope.txt", "/also-nope.txt")

    def test_rename_to_existing_replaces(self, open_volume):
        """POSIX rename(2): an existing regular-file destination is
        atomically replaced (editor atomic-save, macOS ._ sidecars)."""
        vc = open_volume
        vc.write_file("/a.txt", b"a")
        vc.write_file("/b.txt", b"b")
        vc.rename("/a.txt", "/b.txt")
        assert vc.get_entry("/a.txt") is None
        assert vc.read_file("/b.txt") == b"a"

    def test_rename_onto_directory_raises(self, open_volume):
        vc = open_volume
        vc.write_file("/a.txt", b"a")
        vc.mkdir("/d")
        with pytest.raises(IsADirectoryError):
            vc.rename("/a.txt", "/d/")

    def test_read_nonexistent_raises(self, open_volume):
        with pytest.raises(FileNotFoundError):
            open_volume.read_file("/nope.txt")

    def test_read_directory_raises(self, open_volume):
        vc = open_volume
        vc.mkdir("/mydir")
        with pytest.raises(IsADirectoryError):
            vc.read_file("/mydir/")

    def test_stat(self, open_volume):
        vc = open_volume
        vc.write_file("/a.txt", b"hello")
        vc.write_file("/b.txt", b"world!")
        vc.mkdir("/dir")
        stats = vc.stat()
        assert stats["file_count"] == 2
        assert stats["dir_count"] == 1
        assert stats["total_plaintext_size"] == 11  # 5 + 6

    def test_is_dirty_tracking(self, open_volume):
        vc = open_volume
        assert not vc.is_dirty
        vc.write_file("/test.txt", b"data")
        assert vc.is_dirty
        vc.save()
        assert not vc.is_dirty

    def test_multiple_files_persist(self, open_volume, tmp_dir):
        vc = open_volume
        files = {
            "/file1.txt": b"content one",
            "/file2.bin": os.urandom(1024),
            "/sub/file3.dat": os.urandom(vol.VOLUME_CHUNK_SIZE + 500),
        }
        vc.mkdir("/sub")
        for path, data in files.items():
            vc.write_file(path, data)
        vc.save()

        # Reopen
        password = "testpw-testpad"
        final_key = vol.derive_volume_key_single(password, vc.metadata)
        vc2 = vol.VolumeContainer(vc.path, final_key)
        vc2.open()
        for path, data in files.items():
            assert vc2.read_file(path) == data

    def test_overwrite_file(self, open_volume):
        vc = open_volume
        vc.write_file("/test.txt", b"version 1")
        assert vc.read_file("/test.txt") == b"version 1"
        vc.write_file("/test.txt", b"version 2")
        assert vc.read_file("/test.txt") == b"version 2"

    def test_large_file_integrity(self, open_volume):
        vc = open_volume
        # Multi-chunk file
        data = os.urandom(vol.VOLUME_CHUNK_SIZE * 5 + 42)
        vc.write_file("/big.bin", data)
        assert vc.read_file("/big.bin") == data

    def test_save_atomic_no_corruption(self, open_volume, tmp_dir):
        """Verify save writes to temp file then renames."""
        vc = open_volume
        vc.write_file("/test.txt", b"data")

        # Check no .tmp file lingers after save
        vc.save()
        assert not os.path.exists(vc.path + ".tmp")
        assert os.path.isfile(vc.path)


# ── Key derivation tests ───────────────────────────────────────────────────

class TestKeyDerivation:

    def test_single_key_deterministic(self, tmp_dir):
        """Same password + same metadata → same key."""
        path = os.path.join(tmp_dir, "det.qcv")
        meta = vol.create_volume_single(path, "pw123-testpad")
        k1 = vol.derive_volume_key_single("pw123-testpad", meta)
        k2 = vol.derive_volume_key_single("pw123-testpad", meta)
        assert k1 == k2

    def test_shamir_key_from_different_share_combos(self, tmp_dir):
        """Different threshold-size subsets of shares → same key."""
        path = os.path.join(tmp_dir, "sk.qcv")
        meta, shares = vol.create_volume_shamir(path, n=5, k=3)
        k1 = vol.derive_volume_key_shamir(shares[0:3], meta)
        k2 = vol.derive_volume_key_shamir(shares[1:4], meta)
        k3 = vol.derive_volume_key_shamir(shares[2:5], meta)
        assert k1 == k2 == k3


# ── LRU Cache tests ──────────────────────────────────────────────────────

from quantacrypt.core.fuse_ops import (
    LRUCache,
    QuantaCryptFUSE,
    check_fuse_available,
    check_fuse_components,
    get_mounted_volumes,
)


# ── Auth params tests ─────────────────────────────────────────────────────

class TestAuthParams:

    def test_read_auth_params_single(self, tmp_dir):
        """read_volume_auth_params returns auth params for password volumes."""
        path = os.path.join(tmp_dir, "auth.qcv")
        vol.create_volume_single(path, "testpw-testpad")
        header, auth = vol.read_volume_auth_params(path)
        assert auth["mode"] == "single"
        assert "argon_salt" in auth
        assert "kyber_kem_ct" in auth
        assert "kyber_sk_enc_nonce" in auth
        assert "kyber_sk_enc" in auth

    def test_read_auth_params_shamir(self, tmp_dir):
        """read_volume_auth_params returns auth params for shamir volumes."""
        path = os.path.join(tmp_dir, "auth_sh.qcv")
        vol.create_volume_shamir(path, n=3, k=2)
        header, auth = vol.read_volume_auth_params(path)
        assert auth["mode"] == "shamir"
        assert auth["threshold"] == 2
        assert auth["total"] == 3
        assert "kyber_kem_ct" in auth

    def test_derive_key_from_auth_params(self, tmp_dir):
        """Can derive key using auth params read from volume file."""
        path = os.path.join(tmp_dir, "derive.qcv")
        password = "derive-test"
        meta = vol.create_volume_single(path, password)

        # Read auth params from file (no key needed)
        header, auth = vol.read_volume_auth_params(path)

        # Derive key using auth params instead of returned meta
        key = vol.derive_volume_key_single(password, auth)

        # Should be able to open the volume
        vc = vol.VolumeContainer(path, key)
        vc.open()
        assert vc.metadata["mode"] == "single"

    def test_auth_params_persist_through_save(self, tmp_dir):
        """Auth params survive volume save/reopen cycle."""
        path = os.path.join(tmp_dir, "persist.qcv")
        password = "persistpw"
        meta = vol.create_volume_single(path, password)
        key = vol.derive_volume_key_single(password, meta)

        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/test.txt", b"data")
        vc.save()

        # Read auth params from saved file
        _, auth_after = vol.read_volume_auth_params(path)
        assert auth_after["mode"] == "single"
        assert "argon_salt" in auth_after

        # Derive key from auth params and reopen
        key2 = vol.derive_volume_key_single(password, auth_after)
        vc2 = vol.VolumeContainer(path, key2)
        vc2.open()
        assert vc2.read_file("/test.txt") == b"data"


class TestLRUCache:

    def test_put_and_get(self):
        c = LRUCache(max_bytes=1024)
        c.put("a", b"hello")
        assert c.get("a") == b"hello"

    def test_get_missing_returns_none(self):
        c = LRUCache(max_bytes=1024)
        assert c.get("nope") is None

    def test_eviction_by_size(self):
        c = LRUCache(max_bytes=100)
        c.put("a", b"x" * 60)
        c.put("b", b"y" * 60)
        # "a" should have been evicted since 60+60 > 100
        assert c.get("a") is None
        assert c.get("b") == b"y" * 60

    def test_lru_order(self):
        c = LRUCache(max_bytes=100)
        c.put("a", b"x" * 40)
        c.put("b", b"y" * 40)
        # Access "a" to make it recently used
        c.get("a")
        # Now adding "c" should evict "b" (least recently used)
        c.put("c", b"z" * 40)
        assert c.get("b") is None
        assert c.get("a") == b"x" * 40
        assert c.get("c") == b"z" * 40

    def test_invalidate(self):
        c = LRUCache(max_bytes=1024)
        c.put("a", b"hello")
        c.invalidate("a")
        assert c.get("a") is None
        assert c.size == 0

    def test_invalidate_missing_is_noop(self):
        c = LRUCache(max_bytes=1024)
        c.invalidate("nope")  # should not raise

    def test_clear(self):
        c = LRUCache(max_bytes=1024)
        c.put("a", b"hello")
        c.put("b", b"world")
        c.clear()
        assert len(c) == 0
        assert c.size == 0

    def test_overwrite_updates_size(self):
        c = LRUCache(max_bytes=1024)
        c.put("a", b"short")
        assert c.size == 5
        c.put("a", b"much longer value here")
        assert c.size == len(b"much longer value here")
        assert len(c) == 1

    def test_size_and_len(self):
        c = LRUCache(max_bytes=1024)
        c.put("a", b"12345")
        c.put("b", b"678")
        assert len(c) == 2
        assert c.size == 8


# ── FUSE Operations tests ────────────────────────────────────────────────

class TestQuantaCryptFUSE:
    """Test FUSE operations through direct method calls (no actual mount)."""

    @pytest.fixture
    def fuse_fs(self, tmp_dir):
        """Create a volume and return a QuantaCryptFUSE instance."""
        path = os.path.join(tmp_dir, "fuse.qcv")
        password = "fusepw-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        return QuantaCryptFUSE(vc)

    # ── getattr ──

    def test_getattr_root(self, fuse_fs):
        attrs = fuse_fs.getattr("/")
        import stat as st
        assert st.S_ISDIR(attrs["st_mode"])
        assert attrs["st_nlink"] == 2

    def test_getattr_nonexistent(self, fuse_fs):
        with pytest.raises(OSError):
            fuse_fs.getattr("/nope.txt")

    def test_getattr_file(self, fuse_fs):
        fd = fuse_fs.create("/hello.txt", 0o100644)
        fuse_fs.write("/hello.txt", b"hello world", 0, fd)
        fuse_fs.flush("/hello.txt", fd)
        fuse_fs.release("/hello.txt", fd)

        attrs = fuse_fs.getattr("/hello.txt")
        import stat as st
        assert st.S_ISREG(attrs["st_mode"])
        assert attrs["st_size"] == 11

    def test_getattr_directory(self, fuse_fs):
        fuse_fs.mkdir("/mydir", 0o40755)
        attrs = fuse_fs.getattr("/mydir")
        import stat as st
        assert st.S_ISDIR(attrs["st_mode"])

    # ── readdir ──

    def test_readdir_empty(self, fuse_fs):
        entries = fuse_fs.readdir("/")
        assert "." in entries
        assert ".." in entries

    def test_readdir_with_files(self, fuse_fs):
        fd = fuse_fs.create("/a.txt", 0o100644)
        fuse_fs.release("/a.txt", fd)
        fd = fuse_fs.create("/b.txt", 0o100644)
        fuse_fs.release("/b.txt", fd)
        entries = fuse_fs.readdir("/")
        assert "a.txt" in entries
        assert "b.txt" in entries

    # ── mkdir / rmdir ──

    def test_mkdir_and_readdir(self, fuse_fs):
        fuse_fs.mkdir("/docs", 0o40755)
        entries = fuse_fs.readdir("/")
        assert "docs" in entries

    def test_rmdir_empty(self, fuse_fs):
        fuse_fs.mkdir("/empty", 0o40755)
        fuse_fs.rmdir("/empty")
        with pytest.raises(OSError):
            fuse_fs.getattr("/empty")

    def test_rmdir_notempty(self, fuse_fs):
        fuse_fs.mkdir("/stuff", 0o40755)
        fd = fuse_fs.create("/stuff/file.txt", 0o100644)
        fuse_fs.release("/stuff/file.txt", fd)
        with pytest.raises(OSError):
            fuse_fs.rmdir("/stuff")

    # ── create / open / read / write ──

    def test_create_returns_fd(self, fuse_fs):
        fd = fuse_fs.create("/new.txt", 0o100644)
        assert isinstance(fd, int)
        assert fd > 0
        fuse_fs.release("/new.txt", fd)

    def test_write_and_read(self, fuse_fs):
        fd = fuse_fs.create("/test.txt", 0o100644)
        written = fuse_fs.write("/test.txt", b"Hello FUSE!", 0, fd)
        assert written == 11

        data = fuse_fs.read("/test.txt", 100, 0, fd)
        assert data == b"Hello FUSE!"
        fuse_fs.release("/test.txt", fd)

    def test_read_with_offset(self, fuse_fs):
        fd = fuse_fs.create("/off.txt", 0o100644)
        fuse_fs.write("/off.txt", b"abcdefghij", 0, fd)
        data = fuse_fs.read("/off.txt", 3, 5, fd)
        assert data == b"fgh"
        fuse_fs.release("/off.txt", fd)

    def test_write_at_offset(self, fuse_fs):
        fd = fuse_fs.create("/patch.txt", 0o100644)
        fuse_fs.write("/patch.txt", b"AAAA", 0, fd)
        fuse_fs.write("/patch.txt", b"BB", 2, fd)
        data = fuse_fs.read("/patch.txt", 100, 0, fd)
        assert data == b"AABB"  # AA then BB at offset 2 overwrites last two
        fuse_fs.release("/patch.txt", fd)

    def test_open_existing_file(self, fuse_fs):
        # Create and close
        fd = fuse_fs.create("/exist.txt", 0o100644)
        fuse_fs.write("/exist.txt", b"data", 0, fd)
        fuse_fs.flush("/exist.txt", fd)
        fuse_fs.release("/exist.txt", fd)

        # Reopen
        fd2 = fuse_fs.open("/exist.txt", 0)
        data = fuse_fs.read("/exist.txt", 100, 0, fd2)
        assert data == b"data"
        fuse_fs.release("/exist.txt", fd2)

    def test_open_nonexistent(self, fuse_fs):
        with pytest.raises(OSError):
            fuse_fs.open("/nope.txt", 0)

    # ── truncate ──

    def test_truncate_shorter(self, fuse_fs):
        fd = fuse_fs.create("/trunc.txt", 0o100644)
        fuse_fs.write("/trunc.txt", b"long content here", 0, fd)
        fuse_fs.truncate("/trunc.txt", 4, fd)
        data = fuse_fs.read("/trunc.txt", 100, 0, fd)
        assert data == b"long"
        fuse_fs.release("/trunc.txt", fd)

    def test_truncate_longer(self, fuse_fs):
        fd = fuse_fs.create("/trunc2.txt", 0o100644)
        fuse_fs.write("/trunc2.txt", b"hi", 0, fd)
        fuse_fs.truncate("/trunc2.txt", 5, fd)
        data = fuse_fs.read("/trunc2.txt", 100, 0, fd)
        assert data == b"hi\x00\x00\x00"
        fuse_fs.release("/trunc2.txt", fd)

    # ── flush / release ──

    def test_flush_persists_to_volume(self, fuse_fs):
        fd = fuse_fs.create("/flushed.txt", 0o100644)
        fuse_fs.write("/flushed.txt", b"saved", 0, fd)
        fuse_fs.flush("/flushed.txt", fd)

        # Verify data made it to the volume
        data = fuse_fs.volume.read_file("/flushed.txt")
        assert data == b"saved"
        fuse_fs.release("/flushed.txt", fd)

    def test_release_flushes_dirty(self, fuse_fs):
        fd = fuse_fs.create("/rel.txt", 0o100644)
        fuse_fs.write("/rel.txt", b"dirty", 0, fd)
        # Release without explicit flush — should auto-flush
        fuse_fs.release("/rel.txt", fd)

        data = fuse_fs.volume.read_file("/rel.txt")
        assert data == b"dirty"

    def test_release_cleans_up_buffer(self, fuse_fs):
        fd = fuse_fs.create("/cleanup.txt", 0o100644)
        fuse_fs.write("/cleanup.txt", b"temp", 0, fd)
        fuse_fs.release("/cleanup.txt", fd)
        # Buffer should be cleared since no other FDs have it open
        assert "/cleanup.txt" not in fuse_fs._file_buffers

    # ── unlink ──

    def test_unlink(self, fuse_fs):
        fd = fuse_fs.create("/delete.txt", 0o100644)
        fuse_fs.write("/delete.txt", b"bye", 0, fd)
        fuse_fs.release("/delete.txt", fd)

        fuse_fs.unlink("/delete.txt")
        with pytest.raises(OSError):
            fuse_fs.getattr("/delete.txt")

    def test_unlink_while_open_open_returns_enoent(self, fuse_fs):
        """Opening an unlinked-but-still-open path must fail with ENOENT.
        Without this, a second open() would alias the first fd's buffer
        and the final release() would silently discard the new fd's writes
        when it ran the deferred delete."""
        fd = fuse_fs.create("/t.txt", 0o100644)
        fuse_fs.write("/t.txt", b"hi", 0, fd)
        fuse_fs.unlink("/t.txt")
        with pytest.raises(OSError) as exc_info:
            fuse_fs.open("/t.txt", 0)
        assert exc_info.value.errno == errno.ENOENT
        fuse_fs.release("/t.txt", fd)

    def test_unlink_while_open_getattr_returns_enoent(self, fuse_fs):
        fd = fuse_fs.create("/g.txt", 0o100644)
        fuse_fs.unlink("/g.txt")
        with pytest.raises(OSError) as exc_info:
            fuse_fs.getattr("/g.txt")
        assert exc_info.value.errno == errno.ENOENT
        fuse_fs.release("/g.txt", fd)

    def test_unlink_while_open_readdir_filters(self, fuse_fs):
        fd = fuse_fs.create("/listed.txt", 0o100644)
        fuse_fs.create("/kept.txt", 0o100644)
        fuse_fs.unlink("/listed.txt")
        entries = fuse_fs.readdir("/")
        assert "listed.txt" not in entries
        assert "kept.txt" in entries
        fuse_fs.release("/listed.txt", fd)

    def test_unlink_while_open_create_rejects(self, fuse_fs):
        """create() on a path still in _pending_unlink refuses with EEXIST;
        our buffers are vpath-keyed, so accepting the create would corrupt
        the surviving fd's view."""
        fd = fuse_fs.create("/r.txt", 0o100644)
        fuse_fs.unlink("/r.txt")
        with pytest.raises(OSError) as exc_info:
            fuse_fs.create("/r.txt", 0o100644)
        assert exc_info.value.errno == errno.EEXIST
        fuse_fs.release("/r.txt", fd)

    def test_unlink_while_open_rename_rejects(self, fuse_fs):
        fd = fuse_fs.create("/src.txt", 0o100644)
        fuse_fs.unlink("/src.txt")
        with pytest.raises(OSError) as exc_info:
            fuse_fs.rename("/src.txt", "/dst.txt")
        assert exc_info.value.errno == errno.ENOENT
        fuse_fs.release("/src.txt", fd)

    def test_save_all_dirty_does_not_resurrect_unlinked(self, fuse_fs):
        """Regression test for the save_all_dirty() resurrection bug:
        unlink + dirty write + save_all_dirty must NOT persist the file.
        This is the shutdown / unmount / emergency-save path — release()
        may never fire for the still-open fd, so the guard must live in
        save_all_dirty too."""
        fd = fuse_fs.create("/swap.txt", 0o100644)
        fuse_fs.write("/swap.txt", b"secret-swap-data", 0, fd)
        fuse_fs.unlink("/swap.txt")
        # Simulate a shutdown save while the fd is still open.
        fuse_fs.save_all_dirty()
        # After save_all_dirty the pending unlink should have been
        # applied as a real delete (for SIGKILL safety), and the volume
        # must not contain the file.
        assert fuse_fs.volume.get_entry("/swap.txt") is None
        # Closing the now-orphaned fd is a no-op and must not throw.
        fuse_fs.release("/swap.txt", fd)

    def test_unlink_while_open_defers_delete(self, fuse_fs):
        """POSIX unlink-while-open: the file stays accessible through
        already-open fds until the last close, and writes on those fds
        do NOT silently resurrect the file."""
        fd = fuse_fs.create("/tmp.txt", 0o100644)
        fuse_fs.write("/tmp.txt", b"initial", 0, fd)
        fuse_fs.flush("/tmp.txt", fd)

        # Unlink while still open — dir entry stays; path is in pending list.
        fuse_fs.unlink("/tmp.txt")
        assert "/tmp.txt" in fuse_fs._pending_unlink
        # The file should still be openable via the original fd.
        data = fuse_fs.read("/tmp.txt", 100, 0, fd)
        assert data == b"initial"

        # Write through the existing fd after unlink — the inode
        # conceptually still exists, but the data must NOT persist to the
        # volume (last close will free the inode).
        fuse_fs.write("/tmp.txt", b"leaked", 0, fd)
        fuse_fs.release("/tmp.txt", fd)

        # Last release: the pending unlink fires.  Reopening must fail.
        assert "/tmp.txt" not in fuse_fs._pending_unlink
        with pytest.raises(OSError):
            fuse_fs.open("/tmp.txt", 0)
        # And a separate open at the original path must get ENOENT
        # (no silent resurrection with the post-unlink write).
        with pytest.raises(OSError):
            fuse_fs.getattr("/tmp.txt")

    # ── rename ──

    def test_rename(self, fuse_fs):
        fd = fuse_fs.create("/old.txt", 0o100644)
        fuse_fs.write("/old.txt", b"moved", 0, fd)
        fuse_fs.flush("/old.txt", fd)
        fuse_fs.release("/old.txt", fd)

        fuse_fs.rename("/old.txt", "/new.txt")

        with pytest.raises(OSError):
            fuse_fs.getattr("/old.txt")

        fd2 = fuse_fs.open("/new.txt", 0)
        data = fuse_fs.read("/new.txt", 100, 0, fd2)
        assert data == b"moved"
        fuse_fs.release("/new.txt", fd2)

    def test_rename_with_dirty_buffer(self, fuse_fs):
        fd = fuse_fs.create("/src.txt", 0o100644)
        fuse_fs.write("/src.txt", b"buffered", 0, fd)
        # Don't flush — rename with dirty buffer
        fuse_fs.release("/src.txt", fd)
        fuse_fs.rename("/src.txt", "/dst.txt")

        fd2 = fuse_fs.open("/dst.txt", 0)
        data = fuse_fs.read("/dst.txt", 100, 0, fd2)
        assert data == b"buffered"
        fuse_fs.release("/dst.txt", fd2)

    # ── statfs ──

    def test_statfs(self, fuse_fs):
        stats = fuse_fs.statfs("/")
        assert "f_bsize" in stats
        assert stats["f_bsize"] == 4096
        assert stats["f_namemax"] == 255

    # ── Integration: full file lifecycle ──

    def test_full_lifecycle(self, fuse_fs):
        """Create → write → flush → close → reopen → read → rename → delete."""
        # Create and write
        fd = fuse_fs.create("/lifecycle.txt", 0o100644)
        fuse_fs.write("/lifecycle.txt", b"lifecycle data", 0, fd)
        fuse_fs.flush("/lifecycle.txt", fd)
        fuse_fs.release("/lifecycle.txt", fd)

        # Reopen and read
        fd2 = fuse_fs.open("/lifecycle.txt", 0)
        data = fuse_fs.read("/lifecycle.txt", 100, 0, fd2)
        assert data == b"lifecycle data"
        fuse_fs.release("/lifecycle.txt", fd2)

        # Rename
        fuse_fs.rename("/lifecycle.txt", "/renamed.txt")
        entries = fuse_fs.readdir("/")
        assert "renamed.txt" in entries
        assert "lifecycle.txt" not in entries

        # Delete
        fuse_fs.unlink("/renamed.txt")
        entries = fuse_fs.readdir("/")
        assert "renamed.txt" not in entries


# ── FUSE edge cases and coverage boosters ─────────────────────────────────

class TestFUSEEdgeCases:
    """Tests for uncovered branches in fuse_ops.py."""

    @pytest.fixture
    def fuse_fs(self, tmp_dir):
        path = os.path.join(tmp_dir, "edge.qcv")
        password = "edgepw-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        return QuantaCryptFUSE(vc)

    def test_check_fuse_available(self):
        """check_fuse_available returns (bool, str)."""
        available, msg = check_fuse_available()
        assert isinstance(available, bool)
        assert isinstance(msg, str)

    def test_get_mounted_volumes_empty(self):
        """get_mounted_volumes returns a dict."""
        result = get_mounted_volumes()
        assert isinstance(result, dict)

    def test_vpath_without_leading_slash(self, fuse_fs):
        """Paths without / prefix get normalized."""
        result = fuse_fs._vpath("no_slash.txt")
        assert result == "/no_slash.txt"

    def test_vpath_with_leading_slash(self, fuse_fs):
        result = fuse_fs._vpath("/has_slash.txt")
        assert result == "/has_slash.txt"

    def test_dir_vpath_root(self, fuse_fs):
        """Root path stays as /."""
        assert fuse_fs._dir_vpath("/") == "/"

    def test_dir_vpath_adds_trailing_slash(self, fuse_fs):
        assert fuse_fs._dir_vpath("/mydir") == "/mydir/"

    def test_dir_vpath_already_has_slash(self, fuse_fs):
        assert fuse_fs._dir_vpath("/mydir/") == "/mydir/"

    def test_read_lazy_load_without_buffer(self, fuse_fs):
        """read() lazily loads file data if not in buffer."""
        # Create file, flush, release (clears buffer)
        fd = fuse_fs.create("/lazy.txt", 0o100644)
        fuse_fs.write("/lazy.txt", b"lazy data", 0, fd)
        fuse_fs.flush("/lazy.txt", fd)
        fuse_fs.release("/lazy.txt", fd)

        # Manually clear the buffer to force lazy load path
        fuse_fs._file_buffers.pop("/lazy.txt", None)
        fuse_fs.cache.invalidate("/lazy.txt")

        # Read without opening (testing the lazy load in read())
        data = fuse_fs.read("/lazy.txt", 100, 0, 999)
        assert data == b"lazy data"

    def test_write_creates_buffer_if_missing(self, fuse_fs):
        """write() creates a new buffer if file not yet buffered."""
        # Create a file in the volume directly
        fuse_fs.volume.write_file("/direct.txt", b"original")
        fuse_fs.volume.save()

        # Write via FUSE with no buffer loaded
        written = fuse_fs.write("/direct.txt", b"overwritten", 0, 999)
        assert written == 11
        assert "/direct.txt" in fuse_fs._file_buffers

    def test_truncate_loads_from_volume(self, fuse_fs):
        """truncate() loads file from volume if not in buffer."""
        fd = fuse_fs.create("/trunc_load.txt", 0o100644)
        fuse_fs.write("/trunc_load.txt", b"truncate me please", 0, fd)
        fuse_fs.flush("/trunc_load.txt", fd)
        fuse_fs.release("/trunc_load.txt", fd)

        # Clear buffer
        fuse_fs._file_buffers.pop("/trunc_load.txt", None)

        # Truncate loads the surviving prefix from the volume, persists it
        # (no fd will ever flush it) and, since run 14 F-010, drops the
        # buffer again so the plaintext does not stay resident.
        fuse_fs.truncate("/trunc_load.txt", 8)
        assert "/trunc_load.txt" not in fuse_fs._file_buffers
        assert fuse_fs.volume.read_file("/trunc_load.txt") == b"truncate"

    def test_read_uses_chunk_cache(self, fuse_fs):
        """Reads populate and reuse the chunk-granular LRU cache.

        open() no longer materializes the plaintext (partial-range reads);
        the first read decrypts the covering chunk and caches it under the
        vpath+NUL+index key, and a repeat read is served from that entry.
        """
        fd = fuse_fs.create("/cached.txt", 0o100644)
        fuse_fs.write("/cached.txt", b"cached content", 0, fd)
        fuse_fs.flush("/cached.txt", fd)
        fuse_fs.release("/cached.txt", fd)

        # Nothing pre-cached, no buffer materialized by open()
        fd2 = fuse_fs.open("/cached.txt", 0)
        assert "/cached.txt" not in fuse_fs._file_buffers
        assert fuse_fs.cache.get("/cached.txt\x000") is None

        data = fuse_fs.read("/cached.txt", 100, 0, fd2)
        assert data == b"cached content"
        # Chunk 0 is now cached; a second read returns the same bytes
        assert fuse_fs.cache.get("/cached.txt\x000") is not None
        assert fuse_fs.read("/cached.txt", 6, 0, fd2) == b"cached"
        # Still no whole-file buffer for a read-only consumer
        assert "/cached.txt" not in fuse_fs._file_buffers
        fuse_fs.release("/cached.txt", fd2)

    def test_getattr_reports_buffer_size(self, fuse_fs):
        """getattr reports buffer size for modified files."""
        fd = fuse_fs.create("/buf_size.txt", 0o100644)
        fuse_fs.write("/buf_size.txt", b"hello", 0, fd)
        # Don't flush — the buffer has 5 bytes but volume has 0
        attrs = fuse_fs.getattr("/buf_size.txt")
        assert attrs["st_size"] == 5
        fuse_fs.release("/buf_size.txt", fd)

    def test_rename_dirty_file_moves_dirty_flag(self, fuse_fs):
        """rename moves dirty tracking to new path."""
        fd = fuse_fs.create("/dirty_rename.txt", 0o100644)
        fuse_fs.write("/dirty_rename.txt", b"dirty", 0, fd)
        # File is dirty (not flushed)
        assert "/dirty_rename.txt" in fuse_fs._dirty_files

        fuse_fs.release("/dirty_rename.txt", fd)
        # After release, it was flushed, so create dirty state again
        fd2 = fuse_fs.open("/dirty_rename.txt", 0)
        fuse_fs.write("/dirty_rename.txt", b"dirty again", 0, fd2)
        assert "/dirty_rename.txt" in fuse_fs._dirty_files

        fuse_fs.rename("/dirty_rename.txt", "/dirty_moved.txt")
        assert "/dirty_rename.txt" not in fuse_fs._dirty_files
        assert "/dirty_moved.txt" in fuse_fs._dirty_files
        fuse_fs.release("/dirty_moved.txt", fd2)

    def test_flush_noop_for_clean_file(self, fuse_fs):
        """flush() is a no-op for non-dirty files."""
        fd = fuse_fs.create("/clean.txt", 0o100644)
        fuse_fs.write("/clean.txt", b"data", 0, fd)
        fuse_fs.flush("/clean.txt", fd)
        # Flush again — should be a no-op (not dirty)
        fuse_fs.flush("/clean.txt", fd)
        fuse_fs.release("/clean.txt", fd)

    def test_multiple_fds_same_file(self, fuse_fs):
        """Multiple file descriptors can open the same file."""
        fd1 = fuse_fs.create("/shared.txt", 0o100644)
        fuse_fs.write("/shared.txt", b"shared", 0, fd1)
        fuse_fs.flush("/shared.txt", fd1)

        fd2 = fuse_fs.open("/shared.txt", 0)

        # Release first fd — buffer should stay since fd2 is open
        fuse_fs.release("/shared.txt", fd1)
        assert "/shared.txt" in fuse_fs._file_buffers

        # Read via fd2 should work
        data = fuse_fs.read("/shared.txt", 100, 0, fd2)
        assert data == b"shared"

        # Release fd2 — now buffer should be cleaned
        fuse_fs.release("/shared.txt", fd2)
        assert "/shared.txt" not in fuse_fs._file_buffers


# ── check_fuse_components tests ──────────────────────────────────────────────

class TestCheckFuseComponents:
    """Tests for the granular FUSE dependency checker."""

    def test_returns_both_keys(self):
        result = check_fuse_components()
        assert "fusepy" in result
        assert "fuse_backend" in result

    def test_fusepy_key_has_ok_and_detail(self):
        result = check_fuse_components()
        assert "ok" in result["fusepy"]
        assert "detail" in result["fusepy"]
        assert isinstance(result["fusepy"]["ok"], bool)
        assert isinstance(result["fusepy"]["detail"], str)

    def test_fuse_backend_key_has_ok_and_detail(self):
        result = check_fuse_components()
        assert "ok" in result["fuse_backend"]
        assert "detail" in result["fuse_backend"]
        assert isinstance(result["fuse_backend"]["ok"], bool)
        assert isinstance(result["fuse_backend"]["detail"], str)

    def test_fusepy_not_installed(self, monkeypatch):
        """Simulate fusepy not being importable."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "fuse":
                raise ImportError("mock")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        result = check_fuse_components()
        assert result["fusepy"]["ok"] is False
        assert "not installed" in result["fusepy"]["detail"]

    def test_fusepy_installed(self, monkeypatch):
        """Simulate fusepy being importable (mock the import)."""
        import builtins
        import types
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "fuse":
                return types.ModuleType("fuse")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        result = check_fuse_components()
        assert result["fusepy"]["ok"] is True

    def test_no_fuse_backend_linux(self, monkeypatch):
        """Simulate Linux with no FUSE backend."""
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr("shutil.which", lambda _: None)
        monkeypatch.setattr("os.path.exists", lambda p: False)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is False

    def test_fuse_backend_linux_fusermount(self, monkeypatch):
        """Simulate Linux with fusermount available."""
        monkeypatch.setattr("sys.platform", "linux")

        def which(name):
            return "/usr/bin/fusermount" if name == "fusermount" else None

        monkeypatch.setattr("shutil.which", which)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is True

    def test_fuse_backend_darwin_macfuse(self, monkeypatch):
        """Simulate macOS with macFUSE installed."""
        monkeypatch.setattr("sys.platform", "darwin")
        real_isfile = os.path.isfile
        real_isdir = os.path.isdir

        def mock_isfile(p):
            if p in ("/usr/local/lib/libfuse-t.dylib",
                     "/opt/homebrew/lib/libfuse-t.dylib"):
                return False
            return real_isfile(p)

        def mock_isdir(p):
            if p == "/Library/Filesystems/macfuse.fs":
                return True
            if p == "/Library/Filesystems/osxfuse.fs":
                return False
            return real_isdir(p)

        monkeypatch.setattr("os.path.isfile", mock_isfile)
        monkeypatch.setattr("os.path.isdir", mock_isdir)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is True
        assert "macFUSE" in result["fuse_backend"]["detail"]

    def test_fuse_backend_darwin_fuse_t_intel(self, monkeypatch):
        """Simulate macOS with FUSE-T installed at the Intel Homebrew
        prefix (/usr/local)."""
        monkeypatch.setattr("sys.platform", "darwin")
        real_isfile = os.path.isfile

        def mock_isfile(p):
            if p == "/usr/local/lib/libfuse-t.dylib":
                return True
            return real_isfile(p)

        monkeypatch.setattr("os.path.isfile", mock_isfile)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is True
        assert "FUSE-T" in result["fuse_backend"]["detail"]

    def test_fuse_backend_darwin_fuse_t_apple_silicon(self, monkeypatch):
        """Simulate macOS Apple Silicon: Homebrew installs FUSE-T at
        /opt/homebrew/lib, not /usr/local.  Probing only /usr/local
        previously told users on M-series Macs that FUSE-T was missing."""
        monkeypatch.setattr("sys.platform", "darwin")
        real_isfile = os.path.isfile

        def mock_isfile(p):
            if p == "/opt/homebrew/lib/libfuse-t.dylib":
                return True
            if p == "/usr/local/lib/libfuse-t.dylib":
                return False
            return real_isfile(p)

        monkeypatch.setattr("os.path.isfile", mock_isfile)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is True
        assert "FUSE-T" in result["fuse_backend"]["detail"]

    def test_fuse_backend_darwin_none(self, monkeypatch):
        """Simulate macOS with no FUSE backend."""
        monkeypatch.setattr("sys.platform", "darwin")
        monkeypatch.setattr("os.path.isfile", lambda p: False)
        monkeypatch.setattr("os.path.isdir", lambda p: False)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is False

    def test_fuse_backend_darwin_osxfuse(self, monkeypatch):
        """Simulate macOS with legacy osxfuse installed."""
        monkeypatch.setattr("sys.platform", "darwin")
        real_isfile = os.path.isfile
        real_isdir = os.path.isdir

        def mock_isfile(p):
            if p in ("/usr/local/lib/libfuse-t.dylib",
                     "/opt/homebrew/lib/libfuse-t.dylib"):
                return False
            return real_isfile(p)

        def mock_isdir(p):
            if p == "/Library/Filesystems/macfuse.fs":
                return False
            if p == "/Library/Filesystems/osxfuse.fs":
                return True
            return real_isdir(p)

        monkeypatch.setattr("os.path.isfile", mock_isfile)
        monkeypatch.setattr("os.path.isdir", mock_isdir)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is True
        assert "osxfuse" in result["fuse_backend"]["detail"]

    def test_fuse_backend_linux_fusermount3(self, monkeypatch):
        """Simulate Linux with fusermount3 available."""
        monkeypatch.setattr("sys.platform", "linux")

        def which(name):
            return "/usr/bin/fusermount3" if name == "fusermount3" else None

        monkeypatch.setattr("shutil.which", which)
        monkeypatch.setattr("os.path.exists", lambda p: False)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is True

    def test_fuse_backend_linux_dev_fuse(self, monkeypatch):
        """Simulate Linux with /dev/fuse present."""
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr("shutil.which", lambda _: None)

        def mock_exists(p):
            return p == "/dev/fuse"

        monkeypatch.setattr("os.path.exists", mock_exists)
        result = check_fuse_components()
        assert result["fuse_backend"]["ok"] is True


# ── Content hash verification tests ─────────────────────────────────────────

class TestContentHashVerification:
    """Tests for read_file content hash verification."""

    @pytest.fixture
    def open_volume(self, tmp_dir):
        path = os.path.join(tmp_dir, "hash_vol.qcv")
        password = "hashpw-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        return vc

    def test_hash_verified_on_read(self, open_volume):
        """read_file verifies content hash by default."""
        vc = open_volume
        data = b"verified content"
        vc.write_file("/verified.txt", data)
        # Normal read should succeed
        assert vc.read_file("/verified.txt") == data

    def test_hash_mismatch_raises(self, open_volume):
        """read_file raises on tampered content_hash."""
        vc = open_volume
        data = b"tampered content"
        vc.write_file("/tampered.txt", data)
        # Corrupt the stored hash
        vc.dir_index["/tampered.txt"]["content_hash"] = "0" * 64
        with pytest.raises(ValueError, match="Content hash mismatch"):
            vc.read_file("/tampered.txt")

    def test_hash_skip_verification(self, open_volume):
        """read_file with verify_hash=False skips check."""
        vc = open_volume
        data = b"skip hash check"
        vc.write_file("/skip.txt", data)
        vc.dir_index["/skip.txt"]["content_hash"] = "0" * 64
        # Should not raise even with bad hash
        result = vc.read_file("/skip.txt", verify_hash=False)
        assert result == data

    def test_hash_missing_no_error(self, open_volume):
        """read_file works when content_hash is absent from entry."""
        vc = open_volume
        data = b"no hash entry"
        vc.write_file("/nohash.txt", data)
        # Remove the hash field
        del vc.dir_index["/nohash.txt"]["content_hash"]
        # Should still read fine (no hash to check)
        assert vc.read_file("/nohash.txt") == data


# ── Double-mount prevention tests ────────────────────────────────────────────

from quantacrypt.core.fuse_ops import mount_volume, unmount_volume, _mounted_volumes


class TestDoubleMountPrevention:
    """Tests for mount_volume refusing to double-mount."""

    def test_double_mount_raises(self, tmp_dir):
        """mount_volume raises if the same volume file is already mounted."""
        path = os.path.join(tmp_dir, "double.qcv")
        password = "dblpw-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)

        # Simulate an existing mount entry
        mp = os.path.join(tmp_dir, "mnt1")
        _mounted_volumes[mp] = {
            "volume_path": path,
            "volume": vol.VolumeContainer(path, final_key),
            "thread": None,
            "fuse": None,
        }
        try:
            mp2 = os.path.join(tmp_dir, "mnt2")
            with pytest.raises(RuntimeError, match="already mounted"):
                mount_volume(path, final_key, mp2)
        finally:
            _mounted_volumes.pop(mp, None)

    def test_different_volumes_allowed(self, tmp_dir, monkeypatch):
        """mount_volume allows mounting different volume files."""
        path1 = os.path.join(tmp_dir, "vol1.qcv")
        path2 = os.path.join(tmp_dir, "vol2.qcv")
        password = "volpw-testpad"
        meta1 = vol.create_volume_single(path1, password)
        meta2 = vol.create_volume_single(path2, password)
        key1 = vol.derive_volume_key_single(password, meta1)

        mp1 = os.path.join(tmp_dir, "mnt1")
        _mounted_volumes[mp1] = {
            "volume_path": path1,
            "volume": vol.VolumeContainer(path1, key1),
            "thread": None,
            "fuse": None,
        }
        try:
            # Different volume should not trigger double-mount check — we
            # only verify it gets PAST that check.  Force the availability
            # probe to fail deterministically so the test doesn't depend on
            # whether fusepy / a FUSE backend happens to be installed.
            import quantacrypt.core.fuse_ops as fops
            monkeypatch.setattr(
                fops, "check_fuse_available",
                lambda: (False, "fusepy is not installed (forced by test)"),
            )
            key2 = vol.derive_volume_key_single(password, meta2)
            mp2 = os.path.join(tmp_dir, "mnt2")
            with pytest.raises(RuntimeError, match="fusepy"):
                mount_volume(path2, key2, mp2)
        finally:
            _mounted_volumes.pop(mp1, None)


# ── Unmount tests ────────────────────────────────────────────────────────────

def _patched_unmount_subprocess(returncode=0, stderr=""):
    """Patch subprocess.run for unmount tests — no real mount exists, so the
    OS unmount tool would (correctly) fail and unmount_volume would refuse
    to drop tracking.  returncode simulates the tool's exit status."""
    from types import SimpleNamespace
    from unittest.mock import patch
    return patch(
        "subprocess.run",
        return_value=SimpleNamespace(returncode=returncode, stderr=stderr,
                                     stdout=""),
    )


class TestUnmountVolume:
    """Tests for unmount_volume."""

    def test_unmount_saves_dirty_volume(self, tmp_dir):
        """unmount_volume saves a dirty volume."""
        path = os.path.join(tmp_dir, "unmount.qcv")
        password = "umpw-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/test.txt", b"unsaved")

        mp = os.path.join(tmp_dir, "umnt")
        _mounted_volumes[mp] = {
            "volume_path": path,
            "volume": vc,
            "thread": None,
            "fuse": None,
        }
        assert vc.is_dirty
        with _patched_unmount_subprocess():
            unmount_volume(mp)
        assert not vc.is_dirty
        assert mp not in _mounted_volumes

    def test_unmount_unknown_mount_point(self, tmp_dir):
        """unmount_volume refuses to operate on untracked mount points.

        Running diskutil/fusermount against an arbitrary path would risk
        tearing down another app's FUSE mount, so unmount_volume now raises
        ValueError when the caller passes a path we do not own.
        """
        with pytest.raises(ValueError, match="already have been ejected"):
            unmount_volume("/nonexistent/mount/point")

    def test_unmount_clean_volume(self, tmp_dir):
        """unmount_volume works for clean (non-dirty) volumes."""
        path = os.path.join(tmp_dir, "clean_unmount.qcv")
        password = "cleanpw-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()

        mp = os.path.join(tmp_dir, "cmnt")
        _mounted_volumes[mp] = {
            "volume_path": path,
            "volume": vc,
            "thread": None,
            "fuse": None,
        }
        assert not vc.is_dirty
        with _patched_unmount_subprocess():
            unmount_volume(mp)
        assert mp not in _mounted_volumes

    def test_unmount_save_failure_keeps_tracking(self, tmp_dir):
        """If save() fails during unmount, volume stays in tracking dict."""
        path = os.path.join(tmp_dir, "fail_save.qcv")
        password = "failpw-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/test.txt", b"data")

        mp = os.path.join(tmp_dir, "failmnt")
        _mounted_volumes[mp] = {
            "volume_path": path,
            "volume": vc,
            "thread": None,
            "fuse": None,
        }
        # Make save raise
        from unittest.mock import MagicMock
        vc.save = MagicMock(side_effect=OSError("disk full"))
        vc._dirty = True
        # The PRE-unmount save failing keeps the mount alive and raises.
        with pytest.raises(OSError, match="disk full"):
            unmount_volume(mp)
        # Volume should still be tracked so _emergency_save_all can retry
        assert mp in _mounted_volumes
        _mounted_volumes.pop(mp, None)


# ── Mount volume with no FUSE tests ──────────────────────────────────────────

class TestMountVolumeNoFuse:
    """Test mount_volume behavior when fusepy is unavailable."""

    def test_mount_without_fusepy_raises(self, tmp_dir, monkeypatch):
        """mount_volume raises RuntimeError when fusepy is not available.

        The availability is simulated. Previously this test asserted the
        raise without making FUSE unavailable, so it only passed on machines
        with no backend installed. On a machine WITH macFUSE it attempted a
        real mount — and libfuse's fuse_kern_mount() calls fork(), which
        crashed the interpreter in Tcl's atfork handler ("Fatal Python
        error: Illegal instruction"). The crash made the mount fail, which
        raised, which made the test pass. It was green for the wrong reason.
        """
        import quantacrypt.core.fuse_ops as fo
        monkeypatch.setattr(
            fo, "check_fuse_available",
            lambda: (False, "fusepy is not installed (simulated)"))

        path = os.path.join(tmp_dir, "nofuse.qcv")
        password = "nfpw-testpad"
        meta = vol.create_volume_single(path, password)
        key = vol.derive_volume_key_single(password, meta)
        mp = os.path.join(tmp_dir, "nfmnt")
        with pytest.raises(RuntimeError, match="fusepy"):
            mount_volume(path, key, mp)
        # And nothing was registered for a mount that never happened.
        assert mp not in _mounted_volumes


class TestMountVolumeStartup:
    """Exercise the mount_volume startup gate: a FUSE() constructor that
    raises must propagate synchronously instead of leaving a zombie entry
    in _mounted_volumes that a later unmount_volume() would blindly hand
    to diskutil/fusermount."""

    def _make_key_and_path(self, tmp_dir, name):
        path = os.path.join(tmp_dir, name)
        pw = "mount-pw"
        meta = vol.create_volume_single(path, pw)
        key = vol.derive_volume_key_single(pw, meta)
        return path, key

    def test_failed_fuse_startup_does_not_register(self, tmp_dir, monkeypatch):
        """If FUSE() raises inside the worker thread, mount_volume must
        raise and _mounted_volumes must remain unchanged."""
        # Pretend fusepy is importable but the FUSE constructor fails.
        import types
        fake_fuse_module = types.ModuleType("fuse")
        class _FailingFuse:
            def __init__(self, *args, **kwargs):
                raise RuntimeError("simulated FUSE startup failure")
        fake_fuse_module.FUSE = _FailingFuse

        # Install it in sys.modules rather than hijacking builtins.__import__.
        # The import hook intercepted EVERY import in the process while the
        # test ran, and it did not reliably win on Linux — CI reported "DID
        # NOT RAISE" because the real FUSE was reached and mounted. Placing
        # the module directly is deterministic on every platform, and
        # monkeypatch restores the previous entry.
        monkeypatch.setitem(sys.modules, "fuse", fake_fuse_module)

        path, key = self._make_key_and_path(tmp_dir, "zombie.qcv")
        mp = os.path.join(tmp_dir, "zmount")

        before = dict(_mounted_volumes)
        with pytest.raises(RuntimeError, match="FUSE mount failed"):
            mount_volume(path, key, mp)
        # No zombie entry — subsequent unmount would otherwise tear down
        # whatever filesystem happened to be at mp.
        assert dict(_mounted_volumes) == before


# ── Auth params truncation tests ─────────────────────────────────────────────

class TestAuthParamsTruncation:
    """Test error handling for truncated auth params."""

    def test_truncated_auth_params_length(self, tmp_dir):
        """Truncated auth params length field raises ValueError."""
        path = os.path.join(tmp_dir, "trunc_auth.qcv")
        with open(path, "wb") as f:
            vid = os.urandom(16)
            mn = os.urandom(12)
            dn = os.urandom(12)
            vol.write_header(f, vid, mn, dn)
            f.write(b"\x00\x00")  # only 2 bytes for auth params length

        with pytest.raises(ValueError, match="auth params length"):
            vol.read_volume_auth_params(path)

    def test_truncated_auth_params_data(self, tmp_dir):
        """Truncated auth params data raises ValueError."""
        path = os.path.join(tmp_dir, "trunc_auth2.qcv")
        with open(path, "wb") as f:
            vid = os.urandom(16)
            mn = os.urandom(12)
            dn = os.urandom(12)
            vol.write_header(f, vid, mn, dn)
            f.write(struct.pack(">I", 1000))  # claims 1000 bytes
            f.write(b"\x00" * 10)  # only 10

        with pytest.raises(ValueError, match="auth params data"):
            vol.read_volume_auth_params(path)


# ── Corrupt volume open tests ────────────────────────────────────────────────

class TestCorruptVolumeOpen:
    """Tests for VolumeContainer.open() with corrupt data."""

    def test_wrong_key_gives_helpful_error(self, tmp_dir):
        """Opening a volume with wrong key gives a clear error message."""
        path = os.path.join(tmp_dir, "wrongkey.qcv")
        password = "correct-testpad"
        meta = vol.create_volume_single(path, password)
        wrong_key = os.urandom(64)  # random key, not derived from password
        vc = vol.VolumeContainer(path, wrong_key)
        with pytest.raises(ValueError, match="password or key may be incorrect"):
            vc.open()

    def test_truncated_baseline_raises(self, tmp_dir):
        """Truncation inside the baseline section raises at open().

        Compact first so the file lives in the baseline (not the journal);
        a truncated journal tail is the normal crash-recovery shape and is
        tolerated silently, but baseline truncation has no safe recovery.
        """
        path = os.path.join(tmp_dir, "trunc_data.qcv")
        password = "truncpw-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)

        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/big.txt", b"x" * 10000)
        vc.compact()  # force the blob into the baseline

        file_size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.truncate(file_size - 5000)

        vc2 = vol.VolumeContainer(path, final_key)
        with pytest.raises(ValueError, match="truncated"):
            vc2.open()

    def test_truncated_journal_tail_tolerated(self, tmp_dir):
        """Partial journal records at EOF are silently dropped (crash-safe).

        A save() that crashes mid-append leaves an incomplete record after
        the last committed one.  The reader must recover to the last
        committed state without raising, same as a database WAL.
        """
        path = os.path.join(tmp_dir, "trunc_journal.qcv")
        password = "journalpw"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)

        # First save: commit "/a" into the journal.
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/a.txt", b"alpha" * 200)
        vc.save()
        committed_size = os.path.getsize(path)

        # Second save: append another record, then simulate a crash by
        # chopping 10 bytes off the tail — somewhere inside the body.
        vc.write_file("/b.txt", b"beta" * 200)
        vc.save()
        file_size = os.path.getsize(path)
        assert file_size > committed_size
        with open(path, "r+b") as f:
            f.truncate(file_size - 10)

        # Reopen: /a.txt survives, /b.txt is lost.
        vc2 = vol.VolumeContainer(path, final_key)
        vc2.open()
        assert vc2.read_file("/a.txt") == b"alpha" * 200
        assert "/b.txt" not in vc2.dir_index

    def test_save_cleanup_on_error(self, tmp_dir):
        """save() cleans up .tmp file on write error."""
        path = os.path.join(tmp_dir, "cleanup.qcv")
        password = "cleanpw-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/test.txt", b"data")

        # Verify .tmp doesn't linger after successful save
        vc.save()
        assert not os.path.exists(path + ".tmp")

    def test_open_rejects_missing_hmac(self, tmp_dir):
        """Volume whose metadata HMAC has been stripped fails to open.

        Regression guard: VolumeContainer.open() must call _verify_meta_hmac
        after decrypting metadata.  If it skips verification, stripping the
        HMAC field would silently open with undetected tampered auth fields.
        """
        path = os.path.join(tmp_dir, "no_hmac.qcv")
        password = "hmacpw-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)

        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.metadata.pop("hmac", None)
        # compact() forces the mutated metadata to be re-encrypted to disk;
        # save() would append a journal record and leave the on-disk
        # metadata untouched, which is the opposite of what this test wants.
        vc.compact()

        vc2 = vol.VolumeContainer(path, final_key)
        with pytest.raises(ValueError, match="HMAC"):
            vc2.open()

    def test_open_rejects_tampered_hmac(self, tmp_dir):
        """Flipping the stored HMAC byte-for-byte causes open() to fail."""
        path = os.path.join(tmp_dir, "bad_hmac.qcv")
        password = "hmacpw2-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)

        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.metadata["hmac"] = "A" * len(vc.metadata["hmac"])
        vc.compact()  # force metadata rewrite; save() would just append

        vc2 = vol.VolumeContainer(path, final_key)
        with pytest.raises(ValueError, match="authentication failed"):
            vc2.open()

    def test_open_rejects_non_absolute_dir_entry(self, tmp_dir):
        """Directory index with a non-absolute path is rejected."""
        path = os.path.join(tmp_dir, "nonabs.qcv")
        password = "pathpw-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)

        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.dir_index["relative/path.txt"] = {
            "type": "file",
            "size": 0,
            "mode": 0o100644,
            "mtime": 0,
            "nonce": base64.b64encode(b"\x00" * 12).decode(),
            "chunk_count": 0,
            "data_offset": 0,
            "data_length": 0,
        }
        vc._dirty = True
        # Directory tampering only reaches disk via a full rewrite.  save()
        # would append a no-op journal; compact re-encrypts the directory.
        vc.compact()

        vc2 = vol.VolumeContainer(path, final_key)
        with pytest.raises(ValueError, match="must be an absolute path"):
            vc2.open()

    def test_open_rejects_path_traversal_entry(self, tmp_dir):
        """Directory index containing a '..' segment is rejected."""
        path = os.path.join(tmp_dir, "traversal.qcv")
        password = "pathpw-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)

        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.dir_index["/legit/../escape.txt"] = {
            "type": "file",
            "size": 0,
            "mode": 0o100644,
            "mtime": 0,
            "nonce": base64.b64encode(b"\x00" * 12).decode(),
            "chunk_count": 0,
            "data_offset": 0,
            "data_length": 0,
        }
        vc._dirty = True
        # Directory tampering only reaches disk via a full rewrite.  save()
        # would append a no-op journal; compact re-encrypts the directory.
        vc.compact()

        vc2 = vol.VolumeContainer(path, final_key)
        with pytest.raises(ValueError, match="path traversal"):
            vc2.open()


class TestMutatingApiValidation:
    """Mutating VolumeContainer APIs reject the same vpaths that open()
    rejects — keeps writers from bricking a volume by inserting a path
    that would fail the open()-time validation on the next mount."""

    def _open(self, tmp_dir, name="val.qcv"):
        path = os.path.join(tmp_dir, name)
        pw = "val-testpad"
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        return vc

    def test_write_file_rejects_non_absolute(self, tmp_dir):
        vc = self._open(tmp_dir, "w1.qcv")
        with pytest.raises(ValueError, match="must be an absolute path"):
            vc.write_file("relative/file.txt", b"x")

    def test_write_file_rejects_traversal(self, tmp_dir):
        vc = self._open(tmp_dir, "w2.qcv")
        with pytest.raises(ValueError, match="path traversal"):
            vc.write_file("/a/../b.txt", b"x")

    def test_mkdir_rejects_traversal(self, tmp_dir):
        vc = self._open(tmp_dir, "w3.qcv")
        with pytest.raises(ValueError, match="path traversal"):
            vc.mkdir("/foo/../bar")

    def test_rename_rejects_traversal_in_target(self, tmp_dir):
        vc = self._open(tmp_dir, "w4.qcv")
        vc.write_file("/a.txt", b"x")
        with pytest.raises(ValueError, match="path traversal"):
            vc.rename("/a.txt", "/a/../escape.txt")


class TestReadFileBounds:
    """Defensive bounds checks in VolumeContainer.read_file()."""

    def test_read_rejects_negative_chunk_count(self, tmp_dir):
        path = os.path.join(tmp_dir, "neg.qcv")
        pw = "x-testpad"
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/f.txt", b"data")
        vc.dir_index["/f.txt"]["chunk_count"] = -1
        with pytest.raises(ValueError, match="Invalid chunk_count"):
            vc.read_file("/f.txt")

    def test_read_rejects_oversized_chunk_count(self, tmp_dir):
        path = os.path.join(tmp_dir, "over.qcv")
        pw = "x-testpad"
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/f.txt", b"data")  # 1 chunk expected
        vc.dir_index["/f.txt"]["chunk_count"] = 1_000_000
        with pytest.raises(ValueError, match="exceeds what"):
            vc.read_file("/f.txt")

    def test_read_rejects_data_length_mismatch(self, tmp_dir):
        path = os.path.join(tmp_dir, "dlen.qcv")
        pw = "x-testpad"
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/f.txt", b"data")
        vc.dir_index["/f.txt"]["data_length"] = 999999
        with pytest.raises(ValueError, match="data_length"):
            vc.read_file("/f.txt")


class TestLazyBlobLoad:
    """Exercise the lazy-blob path: files written, saved, then read via
    seek-from-disk rather than _file_data cache."""

    def test_reopen_reads_from_disk(self, tmp_dir):
        path = os.path.join(tmp_dir, "lazy.qcv")
        pw = "lazypw-testpad"
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)

        # Write two files, save, then close.
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/a.txt", b"alpha" * 100)
        vc.write_file("/b.txt", b"beta" * 100)
        vc.save()

        # Reopen: _file_data should be empty (lazy).
        vc2 = vol.VolumeContainer(path, final_key)
        vc2.open()
        assert vc2._file_data == {}, (
            "open() should not pre-populate _file_data — blobs are lazy-loaded"
        )

        # Reading should seek from disk and return the original plaintext.
        assert vc2.read_file("/a.txt") == b"alpha" * 100
        assert vc2.read_file("/b.txt") == b"beta" * 100

    def test_save_copies_unmodified_blobs_from_disk(self, tmp_dir):
        """After reopen, add one new file and save — unmodified blobs are
        copied straight from the old container without being held in RAM."""
        path = os.path.join(tmp_dir, "mixed.qcv")
        pw = "mixpw-testpad"
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)

        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        vc.write_file("/old1.txt", b"OLD" * 1000)
        vc.write_file("/old2.txt", b"OLD2" * 1000)
        vc.save()

        # Reopen and add a new file; do NOT touch the existing ones.
        vc2 = vol.VolumeContainer(path, final_key)
        vc2.open()
        vc2.write_file("/new.txt", b"NEW" * 500)
        # Only the newly-written file is in _file_data; save must stream
        # the other two from disk.
        assert set(vc2._file_data.keys()) == {"/new.txt"}
        vc2.save()

        # After save, _file_data is cleared and the volume still reads
        # all three files correctly.
        assert vc2._file_data == {}
        assert vc2.read_file("/old1.txt") == b"OLD" * 1000
        assert vc2.read_file("/old2.txt") == b"OLD2" * 1000
        assert vc2.read_file("/new.txt") == b"NEW" * 500


def _downgrade_to_v1(path: str, key: bytes) -> None:
    """Rewrite a fresh container the way the v1 code wrote it: header version
    1 and sealed ``format_version`` 1 (the first volume commit, 69ccf52, sealed
    the field from the start).  Patching the header word alone no longer
    simulates an old build — open() cross-checks it against the sealed copy
    and reports tampering."""
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
        vol.write_header(f, header["volume_id"], meta_nonce, header["dir_nonce"], version=1)
        vol._write_auth_params(f, auth)
        vol._write_encrypted_block(f, meta_ct)
        vol._write_encrypted_block(f, dir_ct)
        f.write(rest)


class TestFormatV2Journal:
    """Coverage for the v2 append-only journal: replay, auto-compact,
    v1→v2 upgrade, and graceful handling of corrupt / partial records."""

    def _open(self, tmp_dir, name="j.qcv", pw="journal-pw"):
        path = os.path.join(tmp_dir, name)
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)
        return path, final_key

    def test_replay_write_then_delete(self, tmp_dir):
        """write + save + delete + save — replay yields the deleted state."""
        path, key = self._open(tmp_dir, "write_delete.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/a.txt", b"hello")
        vc.save()
        vc.delete("/a.txt")
        vc.save()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "/a.txt" not in vc2.dir_index

    def test_replay_mkdir_then_rmdir(self, tmp_dir):
        path, key = self._open(tmp_dir, "mkdir_rmdir.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.mkdir("/d")
        vc.save()
        vc.delete("/d/")  # delete() on a dir emits rmdir
        vc.save()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "/d/" not in vc2.dir_index

    def test_replay_rename(self, tmp_dir):
        path, key = self._open(tmp_dir, "rename.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/a.txt", b"one")
        vc.save()
        vc.rename("/a.txt", "/b.txt")
        vc.save()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "/a.txt" not in vc2.dir_index
        assert vc2.read_file("/b.txt") == b"one"

    def test_replay_mkdir_persists_directory(self, tmp_dir):
        path, key = self._open(tmp_dir, "mk.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.mkdir("/docs")
        vc.save()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "/docs/" in vc2.dir_index
        assert vc2.dir_index["/docs/"].get("type") == "dir"

    def test_auto_compact_when_dead_space_exceeds_ratio(self, tmp_dir):
        """save() compacts once the bytes that deletes and overwrites left
        behind exceed 30% of the live bytes AND the 8 MB floor.  Live
        writes alone never trigger it: a journal of live blobs costs
        nothing to keep (replay is per record, bodies are seeked over)."""
        path, key = self._open(tmp_dir, "autocompact.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        baseline_bytes = 64 << 20
        vc.write_file("/baseline.bin", b"B" * baseline_bytes)
        vc.compact()
        baseline_size = vc._baseline_size

        # 25 MB of NEW data appends: it is live, so nothing is dead.
        vc.write_file("/y.bin", b"Y" * (25 << 20))
        vc.save()
        assert os.path.getsize(path) - vc._journal_start > (25 << 20)
        assert vc._baseline_size == baseline_size

        # Overwriting a 1 MB file three times leaves 3 MB dead: under the
        # 8 MB floor, so it still appends.
        for i in range(4):
            vc.write_file("/x.bin", bytes([i]) * (1 << 20))
            vc.save()
        dead, live = vc._dead_and_live_bytes()
        assert (3 << 20) < dead < (8 << 20)
        assert vc._baseline_size == baseline_size

        # Deleting /y.bin makes ~28 MB dead: over the floor and over 30% of
        # the ~65 MB live, so this save rolls into a compact.
        vc.delete("/y.bin")
        vc.save()
        assert vc._pending_ops == []
        assert os.path.getsize(path) == vc._journal_start   # journal empty
        assert vc._dead_and_live_bytes()[0] == 0
        assert vc._baseline_size > baseline_size             # absorbed /x.bin
        assert vc._baseline_size < baseline_size + (2 << 20)  # but not /y.bin

    def test_auto_compact_when_the_journal_has_too_many_records(self, tmp_dir, monkeypatch):
        """Replay cost is per record, so the record count is the other
        trigger — independent of how many bytes the records carry."""
        monkeypatch.setattr(vol, "_JOURNAL_COMPACT_RECORDS", 20)
        path, key = self._open(tmp_dir, "records.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        for i in range(20):
            vc.write_file(f"/f{i}.txt", b"x")
            vc.save()
        assert vc._journal_records == 20
        assert os.path.getsize(path) > vc._journal_start
        vc.write_file("/f20.txt", b"x")
        vc.save()
        assert vc._journal_records == 0
        assert os.path.getsize(path) == vc._journal_start
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert len(vc2.dir_index) == 21

    def test_v1_container_upgrades_on_save(self, tmp_dir):
        """Hand-roll a v1 container bytewise, open it, save, and verify the
        on-disk header is bumped to the journal layout's version.  Not to
        VOLUME_FORMAT_VERSION: the KEM/parameter fields that version 3
        names are creation-time facts a compact cannot add, and keeping a
        container at the lowest version that describes it lets older builds
        keep opening it."""
        path, key = self._open(tmp_dir, "v1.qcv")
        _downgrade_to_v1(path, key)

        vc = vol.VolumeContainer(path, key)
        vc.open()
        assert vc.header["version"] == 1
        vc.write_file("/new.txt", b"upgraded")
        vc.save()  # v1 container always compacts

        # Confirm on-disk header is now v2.
        with open(path, "rb") as f:
            f.seek(6)
            version = struct.unpack(">I", f.read(4))[0]
        assert version == vol._JOURNAL_FORMAT_VERSION == 2

    def test_v1_container_rejects_trailing_bytes(self, tmp_dir):
        """A v1 container with bytes past the baseline is corrupt."""
        path, key = self._open(tmp_dir, "v1_trail.qcv")
        _downgrade_to_v1(path, key)
        with open(path, "ab") as f:
            f.write(b"junk-bytes-pretending-to-be-v2-journal")

        vc = vol.VolumeContainer(path, key)
        with pytest.raises(ValueError, match="Trailing bytes"):
            vc.open()

    def test_save_noop_when_clean(self, tmp_dir):
        """save() on a container with no pending changes is a no-op."""
        path, key = self._open(tmp_dir, "noop.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        size_before = os.path.getsize(path)
        mtime_before = os.path.getmtime(path)
        vc.save()
        assert os.path.getsize(path) == size_before
        # The file must not be rewritten when nothing changed (mtime may
        # be equal even if we touched it, so just check content).
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.dir_index == {}

    def test_corrupt_journal_header_stops_replay(self, tmp_dir):
        """A flipped bit in a journal record's ciphertext header stops
        replay at that record; earlier records still apply."""
        path, key = self._open(tmp_dir, "corrupt_rec.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/a.txt", b"alpha")
        vc.save()
        journal_start = vc._journal_start
        vc.write_file("/b.txt", b"beta")
        vc.save()

        # Flip one byte of /b.txt's record header ciphertext.  The second
        # record's nonce lives at journal_start + len(first record).
        # Easy approach: corrupt the first byte after /a.txt's body.
        first_record_end = (
            vc._data_offset + vc.dir_index["/a.txt"]["data_offset"]
            + vc.dir_index["/a.txt"]["data_length"]
        )
        with open(path, "r+b") as f:
            f.seek(first_record_end)
            raw = f.read(1)
            f.seek(first_record_end)
            f.write(bytes([raw[0] ^ 0xFF]))

        # Reopening must preserve /a.txt but drop /b.txt.
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.read_file("/a.txt") == b"alpha"
        assert "/b.txt" not in vc2.dir_index

    def test_read_after_journal_append(self, tmp_dir):
        """Files in the journal region are readable via _get_blob seek."""
        path, key = self._open(tmp_dir, "read_journal.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/j.txt", b"journaled" * 500)
        vc.save()
        # Same instance: blob is cleared from _file_data after save, so
        # read must seek into the journal region.
        assert vc._file_data == {}
        assert vc.read_file("/j.txt", verify_hash=False) == b"journaled" * 500

    def test_reopen_after_compact_bounds_check(self, tmp_dir):
        """Open() must bounds-check baseline entries after a compact.

        Covers the baseline loop in open() — prior tests only reopened
        volumes whose baseline dir_index was empty (changes stayed in the
        journal), so the bounds check had nothing to iterate over.
        """
        path, key = self._open(tmp_dir, "baseline_loop.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/base1.txt", b"one" * 100)
        vc.write_file("/base2.txt", b"two" * 100)
        vc.compact()

        # Reopen — baseline dir_index now has two real file entries that
        # the bounds-check loop must walk before declaring the container
        # consistent.
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert set(vc2.dir_index) == {"/base1.txt", "/base2.txt"}
        assert vc2.read_file("/base1.txt") == b"one" * 100

    def test_an_emptied_volume_shrinks(self, tmp_dir):
        """Fill, then delete everything: with no live bytes at all, the dead
        blobs exceed the floor and save() compacts back to an empty
        container.  Before the dead-space rule a volume kept its full size
        forever after a delete-all, with no compact action in either UI."""
        path, key = self._open(tmp_dir, "tiny.qcv")
        empty_size = os.path.getsize(path)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        assert vc._baseline_size == 0
        # A 10 MB write is live data: it appends, whatever the baseline.
        vc.write_file("/big.bin", b"Q" * (10 << 20))
        vc.save()
        assert os.path.getsize(path) - vc._journal_start > (10 << 20)
        assert vc._baseline_size == 0
        vc.delete("/big.bin")
        vc.save()
        assert os.path.getsize(path) == vc._journal_start
        assert os.path.getsize(path) < empty_size + 2048
        assert vol.VolumeContainer(path, key).open() is None

    def test_write_then_rename_persists_data(self, tmp_dir):
        """Atomic-save pattern: write /tmp + rename /tmp -> /final + save
        must leave /final readable on reopen.  Pre-fix, the rename re-keyed
        _file_data but _pending_ops still referenced /tmp, so the journal
        emitted an orphan write record with an empty body (skipped by the
        guard) followed by a rename that hit a missing source (skipped in
        replay) — silent data loss on every editor-style save."""
        path, key = self._open(tmp_dir, "atomic.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/doc.tmp", b"precious data" * 100)
        vc.rename("/doc.tmp", "/doc.txt")
        vc.save()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "/doc.tmp" not in vc2.dir_index
        assert vc2.read_file("/doc.txt") == b"precious data" * 100

    def test_write_rename_rewrite_keeps_last_content(self, tmp_dir):
        """write A + rename A->B + write B (new content) = end state B."""
        path, key = self._open(tmp_dir, "atomic2.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/tmp.txt", b"first")
        vc.rename("/tmp.txt", "/final.txt")
        vc.write_file("/final.txt", b"second")
        vc.save()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.read_file("/final.txt") == b"second"
        assert "/tmp.txt" not in vc2.dir_index

    def test_replay_rejects_malformed_vpath(self, tmp_dir):
        """Replay skips records whose vpath is missing/non-absolute instead
        of polluting the dir_index with junk."""
        path, key = self._open(tmp_dir, "badpath.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        # Append a hand-crafted journal record with a bogus vpath.
        with open(path, "r+b") as f:
            f.seek(0, 2)
            vol._write_journal_record(
                f, key,
                {"type": "write", "vpath": "no-leading-slash",
                 "size": 0, "mode": 0, "mtime": 0, "nonce": "",
                 "chunk_count": 0, "content_hash": ""},
                b"",
            )
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "no-leading-slash" not in vc2.dir_index
        assert "/no-leading-slash" not in vc2.dir_index


# ── Graceful shutdown tests ─────────────────────────────────────────────────

import signal
from unittest.mock import MagicMock, patch

from quantacrypt.core.fuse_ops import (
    _emergency_save_all,
    _ensure_shutdown_handlers,
    _signal_handler,
    _shutdown_lock,
)


class TestGracefulShutdown:
    """Tests for atexit / signal-based auto-save on exit."""

    def _make_mounted(self, tmp_dir, dirty=True):
        """Helper: create a volume and register it in _mounted_volumes."""
        path = os.path.join(tmp_dir, "shutdown.qcv")
        password = "shutpw-testpad"
        meta = vol.create_volume_single(path, password)
        final_key = vol.derive_volume_key_single(password, meta)
        vc = vol.VolumeContainer(path, final_key)
        vc.open()
        if dirty:
            vc.write_file("/dirty.txt", b"unsaved data")
        _mounted_volumes["/mnt/test_shutdown"] = {
            "volume": vc,
            "volume_path": path,
            "thread": None,
            "fuse": None,
        }
        return vc, path

    def test_emergency_save_dirty_volume(self, tmp_dir):
        """_emergency_save_all saves dirty volumes."""
        _mounted_volumes.clear()
        vc, path = self._make_mounted(tmp_dir, dirty=True)
        assert vc.is_dirty

        _emergency_save_all()

        # Volume should have been saved — reopen and verify
        vc2 = vol.VolumeContainer(path, vc.final_key)
        vc2.open()
        data = vc2.read_file("/dirty.txt")
        assert data == b"unsaved data"

        _mounted_volumes.clear()

    def test_emergency_save_clean_volume_skipped(self, tmp_dir):
        """_emergency_save_all skips clean (non-dirty) volumes."""
        _mounted_volumes.clear()
        vc, path = self._make_mounted(tmp_dir, dirty=False)
        assert not vc.is_dirty

        # Patch save to verify it's NOT called
        vc.save = MagicMock()
        _emergency_save_all()
        vc.save.assert_not_called()

        _mounted_volumes.clear()

    def test_emergency_save_handles_errors(self, tmp_dir):
        """_emergency_save_all logs but doesn't raise on save failure."""
        _mounted_volumes.clear()
        vc, path = self._make_mounted(tmp_dir, dirty=True)

        # Make save() raise to simulate disk error
        vc.save = MagicMock(side_effect=OSError("disk full"))
        vc._dirty = True  # ensure is_dirty returns True

        # Should not raise
        _emergency_save_all()

        _mounted_volumes.clear()

    def test_emergency_save_multiple_volumes(self, tmp_dir):
        """_emergency_save_all iterates all mounted volumes."""
        _mounted_volumes.clear()
        saved = []

        for i in range(3):
            path = os.path.join(tmp_dir, f"multi_{i}.qcv")
            password = f"pw{i}-testpad"
            meta = vol.create_volume_single(path, password)
            final_key = vol.derive_volume_key_single(password, meta)
            vc = vol.VolumeContainer(path, final_key)
            vc.open()
            vc.write_file(f"/file{i}.txt", f"data{i}".encode())

            _mounted_volumes[f"/mnt/vol{i}"] = {
                "volume": vc,
                "volume_path": path,
                "thread": None,
                "fuse": None,
            }

        _emergency_save_all()

        # Verify all three volumes were saved
        for i in range(3):
            path = os.path.join(tmp_dir, f"multi_{i}.qcv")
            info = _mounted_volumes[f"/mnt/vol{i}"]
            vc2 = vol.VolumeContainer(path, info["volume"].final_key)
            vc2.open()
            assert vc2.read_file(f"/file{i}.txt") == f"data{i}".encode()

        _mounted_volumes.clear()

    def test_signal_handler_calls_save(self, tmp_dir):
        """_signal_handler saves volumes before re-raising signal."""
        _mounted_volumes.clear()
        vc, path = self._make_mounted(tmp_dir, dirty=True)

        with patch("quantacrypt.core.fuse_ops.signal.signal"), \
             patch("quantacrypt.core.fuse_ops.os.kill") as mock_kill:
            _signal_handler(signal.SIGTERM, None)

        # Volume should have been saved
        vc2 = vol.VolumeContainer(path, vc.final_key)
        vc2.open()
        assert vc2.read_file("/dirty.txt") == b"unsaved data"

        # os.kill should have been called to re-raise
        mock_kill.assert_called_once_with(os.getpid(), signal.SIGTERM)

        _mounted_volumes.clear()

    def test_ensure_shutdown_registers_once(self):
        """_ensure_shutdown_handlers only registers each half once."""
        import quantacrypt.core.fuse_ops as fops

        orig_atexit = fops._atexit_registered
        orig_signals = fops._signals_registered
        fops._atexit_registered = False
        fops._signals_registered = False
        try:
            with patch("quantacrypt.core.fuse_ops.atexit.register") \
                    as mock_atexit, \
                 patch("quantacrypt.core.fuse_ops.signal.signal") \
                    as mock_signal:
                _ensure_shutdown_handlers()
                assert mock_atexit.call_count == 1
                assert mock_signal.call_count == 2  # SIGTERM + SIGINT

                # Second call should be a no-op for both halves
                _ensure_shutdown_handlers()
                assert mock_atexit.call_count == 1
                assert mock_signal.call_count == 2
        finally:
            fops._atexit_registered = orig_atexit
            fops._signals_registered = orig_signals

    def test_ensure_shutdown_handles_non_main_thread(self):
        """A failed off-main-thread signal install must NOT latch.

        Regression for the review's F-008: the old single flag recorded the
        worker thread's failed signal.signal() as done, so the GUI (which
        always mounts on a worker) never got SIGTERM emergency-save
        handlers.  The signal half must stay pending until a main-thread
        call succeeds.
        """
        import quantacrypt.core.fuse_ops as fops

        orig_atexit = fops._atexit_registered
        orig_signals = fops._signals_registered
        fops._atexit_registered = False
        fops._signals_registered = False
        try:
            with patch("quantacrypt.core.fuse_ops.atexit.register") \
                    as mock_atexit, \
                 patch("quantacrypt.core.fuse_ops.signal.signal",
                       side_effect=ValueError("not main thread")):
                # Should not raise even though signal.signal fails
                _ensure_shutdown_handlers()
                assert mock_atexit.call_count == 1
            # atexit half latched; signal half must remain pending
            assert fops._atexit_registered is True
            assert fops._signals_registered is False

            # A later (main-thread) call installs the handlers and latches
            with patch("quantacrypt.core.fuse_ops.atexit.register") \
                    as mock_atexit2, \
                 patch("quantacrypt.core.fuse_ops.signal.signal") \
                    as mock_signal:
                fops.install_shutdown_handlers()
                assert mock_atexit2.call_count == 0  # already registered
                assert mock_signal.call_count == 2
            assert fops._signals_registered is True
        finally:
            fops._atexit_registered = orig_atexit
            fops._signals_registered = orig_signals


# ── Post-review regression tests (journal crash-safety cluster) ─────────────

class TestJournalCrashSafety:
    """Regression tests for the review's data-loss cluster: F-004 (saves
    after a crash-truncated tail must remain reachable), F-008 (tamper-vs-
    crash classification), F-005 (failed compact must be retryable), and
    F-006 (delete/rename of persisted paths must not resurrect).  See
    docs/design/volume-journal-crash-safety-fixes.md."""

    def _open(self, tmp_dir, name="crash.qcv", pw="crash-pw"):
        path = os.path.join(tmp_dir, name)
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)
        return path, final_key

    def test_saves_after_truncated_tail_survive_reopen(self, tmp_dir):
        """F-004: after crash recovery, new saves must truncate the garbage
        tail and land where replay can reach them — pre-fix they were
        appended past the garbage and silently lost on every future open."""
        path, key = self._open(tmp_dir)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/a.txt", b"alpha" * 200)
        vc.save()
        vc.write_file("/b.txt", b"beta" * 200)
        vc.save()
        # Crash shape: chop 10 bytes off the tail (inside /b's record).
        with open(path, "r+b") as f:
            f.truncate(os.path.getsize(path) - 10)

        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.read_file("/a.txt") == b"alpha" * 200
        assert "/b.txt" not in vc2.dir_index
        assert vc2.journal_suspicious is False  # truncation == crash shape

        # The save after recovery is what pre-fix versions lost forever.
        vc2.write_file("/c.txt", b"gamma" * 200)
        vc2.save()

        vc3 = vol.VolumeContainer(path, key)
        vc3.open()
        assert vc3.read_file("/a.txt") == b"alpha" * 200
        assert vc3.read_file("/c.txt") == b"gamma" * 200
        assert "/b.txt" not in vc3.dir_index

    def test_complete_record_corruption_flags_suspicious(self, tmp_dir):
        """F-008: a fully-present journal record that fails auth is the
        tamper/corruption shape and must be flagged — unlike crash tails,
        which run out of bytes at EOF."""
        path, key = self._open(tmp_dir, "tamper.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/a.txt", b"alpha")
        vc.save()
        second_record_start = vc._journal_end  # /b's record starts here
        vc.write_file("/b.txt", b"beta")
        vc.save()
        # Flip a byte inside /b's record header ciphertext (record fully
        # present on disk — auth failure, not truncation).
        with open(path, "r+b") as f:
            f.seek(second_record_start + 20)
            raw = f.read(1)
            f.seek(second_record_start + 20)
            f.write(bytes([raw[0] ^ 0xFF]))

        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.read_file("/a.txt") == b"alpha"
        assert "/b.txt" not in vc2.dir_index
        assert vc2.journal_suspicious is True

    def test_failed_compact_is_retryable(self, tmp_dir, monkeypatch):
        """F-005: a compact that fails mid-write (disk full) must leave both
        disk and memory intact — reads keep working and a retry succeeds.
        Pre-fix, dir_index offsets were mutated before writing, so the
        retry copied garbage byte ranges and destroyed the container."""
        path, key = self._open(tmp_dir, "retry.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/a.txt", b"A" * 5000)
        vc.write_file("/b.txt", b"B" * 5000)
        vc.compact()  # both files into the baseline
        vc.write_file("/c.txt", b"C" * 5000)  # pending in _file_data

        def boom(fd):
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(vol.os, "fsync", boom)
        with pytest.raises(OSError):
            vc.compact()
        monkeypatch.undo()

        # In-memory state untouched: reads still resolve the right bytes,
        # and no partial .tmp is left beside the original.
        assert vc.read_file("/a.txt") == b"A" * 5000
        assert not os.path.exists(path + ".tmp")

        # The natural next step — retry — must succeed and preserve all.
        vc.compact()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.read_file("/a.txt") == b"A" * 5000
        assert vc2.read_file("/b.txt") == b"B" * 5000
        assert vc2.read_file("/c.txt") == b"C" * 5000

    def test_delete_of_persisted_file_stays_deleted(self, tmp_dir):
        """F-006: edit-then-delete of a path that persists on disk must
        emit a tombstone — pre-fix both ops were coalesced away and the
        old file resurrected on remount."""
        path, key = self._open(tmp_dir, "tombstone.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/x.txt", b"original")
        vc.save()  # /x persists in the journal
        vc.write_file("/x.txt", b"edited")
        vc.delete("/x.txt")
        vc.save()

        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "/x.txt" not in vc2.dir_index

    def test_rename_of_persisted_file_leaves_no_ghost(self, tmp_dir):
        """F-006: edit-then-rename of a persisted path must tombstone the
        old name — pre-fix remount showed both the new file and a
        resurrected old one with pre-edit content."""
        path, key = self._open(tmp_dir, "ghost.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/x.txt", b"original")
        vc.save()
        vc.write_file("/x.txt", b"edited")
        vc.rename("/x.txt", "/y.txt")
        vc.save()

        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "/x.txt" not in vc2.dir_index
        assert vc2.read_file("/y.txt") == b"edited"

    def test_unpersisted_write_delete_still_drops_both(self, tmp_dir):
        """Coalescing still drops write+delete pairs for paths that never
        reached disk (no pointless tombstones)."""
        path, key = self._open(tmp_dir, "droppair.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        size_before = os.path.getsize(path)
        vc.write_file("/tmp.txt", b"scratch")
        vc.delete("/tmp.txt")
        vc.save()
        assert os.path.getsize(path) == size_before  # nothing emitted

        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.dir_index == {}


class TestFUSEDurability:
    """F-001: FUSE flush/fsync must persist to the on-disk journal at the
    moment the kernel is told data is flushed, not at unmount."""

    def _make(self, tmp_dir):
        path = os.path.join(tmp_dir, "durable.qcv")
        meta = vol.create_volume_single(path, "durapw-testpad")
        key = vol.derive_volume_key_single("durapw-testpad", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        return path, key, QuantaCryptFUSE(vc)

    def test_flush_persists_to_disk_immediately(self, tmp_dir):
        path, key, fs = self._make(tmp_dir)
        fd = fs.create("/doc.txt", 0o100644)
        fs.write("/doc.txt", b"must survive a crash", 0, fd)
        fs.flush("/doc.txt", fd)
        # Simulated crash: no release, no unmount, no save_all_dirty —
        # a completely fresh container must already see the write.
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.read_file("/doc.txt") == b"must survive a crash"

    def test_fsync_op_persists(self, tmp_dir):
        path, key, fs = self._make(tmp_dir)
        fd = fs.create("/f.txt", 0o100644)
        fs.write("/f.txt", b"fsynced", 0, fd)
        assert fs.fsync("/f.txt", 0, fd) == 0
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.read_file("/f.txt") == b"fsynced"

    def test_unlink_persists_to_disk_immediately(self, tmp_dir):
        path, key, fs = self._make(tmp_dir)
        fd = fs.create("/gone.txt", 0o100644)
        fs.write("/gone.txt", b"data", 0, fd)
        fs.flush("/gone.txt", fd)
        fs.release("/gone.txt", fd)
        fs.unlink("/gone.txt")
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "/gone.txt" not in vc2.dir_index

    def test_flush_bounds_file_data_memory(self, tmp_dir):
        """Persisting on flush clears the container's pending-blob dict —
        pre-fix it retained every blob written during the mount session."""
        path, key, fs = self._make(tmp_dir)
        fd = fs.create("/big.bin", 0o100644)
        fs.write("/big.bin", b"Z" * 100_000, 0, fd)
        fs.flush("/big.bin", fd)
        assert fs.volume._file_data == {}


class TestFuseOperationsContract:
    """F-007: fusepy dispatches by *calling* the operations object — only a
    fuse.Operations subclass survives a real mount (a plain class 'mounts'
    and then fails every op with EINVAL)."""

    def test_subclasses_fuse_operations(self):
        # Not importorskip: fusepy raises OSError (not ImportError) when
        # the package is installed but no libfuse backend loads — the
        # skip must cover both, or a backend-less machine errors here.
        try:
            import fuse
        except (ImportError, OSError) as exc:
            pytest.skip(f"fusepy/libfuse unavailable: {exc}")
        assert issubclass(QuantaCryptFUSE, fuse.Operations)

    def test_chmod_and_utimens(self, tmp_dir):
        path = os.path.join(tmp_dir, "attr.qcv")
        meta = vol.create_volume_single(path, "attrpw-testpad")
        key = vol.derive_volume_key_single("attrpw-testpad", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        fs = QuantaCryptFUSE(vc)
        fd = fs.create("/m.txt", 0o100644)
        fs.release("/m.txt", fd)
        assert fs.chmod("/m.txt", 0o100600) == 0
        assert fs.getattr("/m.txt")["st_mode"] == 0o100600
        assert fs.utimens("/m.txt", (1000, 2000)) == 0
        assert fs.getattr("/m.txt")["st_mtime"] == 2000
        with pytest.raises(OSError):
            fs.chmod("/nope.txt", 0o600)
        with pytest.raises(OSError):
            fs.utimens("/nope.txt", None)


class TestRenameReplaceAndErrno:
    """F-015 + F-021 regressions, promoted to blockers by the live-mount
    validation: macOS renames AppleDouble sidecars over existing paths, and
    errno-less exceptions make fusepy return garbage error values to the
    kernel (`e.errno > 0` on None → TypeError inside fusepy's wrapper)."""

    def _open(self, tmp_dir, name="rr.qcv", pw="rr-pw-testpad"):
        path = os.path.join(tmp_dir, name)
        meta = vol.create_volume_single(path, pw)
        final_key = vol.derive_volume_key_single(pw, meta)
        return path, final_key

    def test_rename_over_persisted_dest_emits_tombstone(self, tmp_dir):
        """Replacing a persisted destination must tombstone it, or replay
        resurrects the old content on the next open (F-006 interaction)."""
        path, key = self._open(tmp_dir)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/final.txt", b"old-version")
        vc.save()  # destination persists
        vc.write_file("/final.txt.tmp", b"new-version")
        vc.rename("/final.txt.tmp", "/final.txt")
        vc.save()

        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert "/final.txt.tmp" not in vc2.dir_index
        assert vc2.read_file("/final.txt") == b"new-version"

    def test_container_exceptions_carry_errno(self, tmp_dir):
        """Every VolumeContainer refusal must have a real errno for the
        FUSE layer (fusepy maps OSError to -e.errno)."""
        path, key = self._open(tmp_dir, "errno.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/f.txt", b"x")
        vc.mkdir("/d")
        vc.write_file("/d/child.txt", b"y")

        with pytest.raises(FileNotFoundError) as ei:
            vc.read_file("/nope")
        assert ei.value.errno == errno.ENOENT
        with pytest.raises(IsADirectoryError) as ei:
            vc.read_file("/d/")
        assert ei.value.errno == errno.EISDIR
        with pytest.raises(FileNotFoundError) as ei:
            vc.delete("/nope")
        assert ei.value.errno == errno.ENOENT
        with pytest.raises(OSError) as ei:
            vc.delete("/d/")
        assert ei.value.errno == errno.ENOTEMPTY
        with pytest.raises(FileNotFoundError) as ei:
            vc.rename("/nope", "/other")
        assert ei.value.errno == errno.ENOENT
        with pytest.raises(IsADirectoryError) as ei:
            vc.rename("/f.txt", "/d/")
        assert ei.value.errno == errno.EISDIR

    def test_fuse_rename_over_open_dest_drops_stale_buffer(self, tmp_dir):
        """FUSE rename over an existing path must not leave the replaced
        destination's old bytes in the buffer/cache layer."""
        path, key = self._open(tmp_dir, "stale.qcv")
        vc = vol.VolumeContainer(path, key)
        vc.open()
        fs = QuantaCryptFUSE(vc)
        fd_b = fs.create("/b.txt", 0o100644)
        fs.write("/b.txt", b"old-dest", 0, fd_b)
        fs.flush("/b.txt", fd_b)
        fs.release("/b.txt", fd_b)
        fd_a = fs.create("/a.txt", 0o100644)
        fs.write("/a.txt", b"new-content", 0, fd_a)
        fs.flush("/a.txt", fd_a)
        fs.release("/a.txt", fd_a)
        # Open dest so it has a live buffer, then rename over it.
        fd = fs.open("/b.txt", os.O_RDONLY)
        fs.rename("/a.txt", "/b.txt")
        assert fs.read("/b.txt", 100, 0, fd) == b"new-content"


# ── Review run 2 regression tests (Medium+ fix batch) ───────────────────────
# See docs/design/review-2026-09-medium-fixes.md.

class TestCoalescingReplaySimulation:
    """F-002: tombstone decisions must simulate on-replay existence, not
    consult the stale last-save snapshot — a rename of a baseline path in
    the same batch materializes its destination on replay."""

    def _open(self, tmp_dir, name):
        path = os.path.join(tmp_dir, name)
        meta = vol.create_volume_single(path, "coal-pw-testpad")
        key = vol.derive_volume_key_single("coal-pw-testpad", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        return path, key, vc

    def test_baseline_rename_then_write_delete_stays_deleted(self, tmp_dir):
        # write /x; save; [rename /x→/y; write /y; delete /y]; save
        path, key, vc = self._open(tmp_dir, "resA.qcv")
        vc.write_file("/x.txt", b"old content")
        vc.save()
        vc.rename("/x.txt", "/y.txt")
        vc.write_file("/y.txt", b"new content")
        vc.delete("/y.txt")
        vc.save()

        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.get_entry("/y.txt") is None, \
            "deleted file resurrected with renamed-in baseline content"
        assert vc2.get_entry("/x.txt") is None

    def test_baseline_rename_then_write_rename_leaves_no_ghost(self, tmp_dir):
        # write /x; save; [rename /x→/y; write /y; rename /y→/z]; save
        path, key, vc = self._open(tmp_dir, "resB.qcv")
        vc.write_file("/x.txt", b"old content")
        vc.save()
        vc.rename("/x.txt", "/y.txt")
        vc.write_file("/y.txt", b"new content")
        vc.rename("/y.txt", "/z.txt")
        vc.save()

        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.get_entry("/y.txt") is None, \
            "intermediate rename destination resurrected on replay"
        assert vc2.get_entry("/x.txt") is None
        assert vc2.read_file("/z.txt") == b"new content"

    def test_unpersisted_write_delete_still_drops_both(self, tmp_dir):
        # Never-persisted pair must still coalesce away (no spurious
        # tombstones for paths nothing materializes).
        path, key, vc = self._open(tmp_dir, "resC.qcv")
        vc.write_file("/tmp.txt", b"scratch")
        vc.delete("/tmp.txt")
        assert vc._coalesce_pending_ops() == []


class TestDirectoryRename:
    """F-001: renaming a directory must re-key the whole subtree —
    previously it failed ENOENT through FUSE, and the naive fix would
    have orphaned every child."""

    def _open(self, tmp_dir, name):
        path = os.path.join(tmp_dir, name)
        meta = vol.create_volume_single(path, "dir-pw-testpad")
        key = vol.derive_volume_key_single("dir-pw-testpad", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        return path, key, vc

    def _populate(self, vc):
        vc.mkdir("/docs")
        vc.mkdir("/docs/sub")
        vc.write_file("/docs/a.txt", b"alpha")
        vc.write_file("/docs/sub/b.txt", b"beta")

    def test_container_rename_dir_rekeys_subtree(self, tmp_dir):
        path, key, vc = self._open(tmp_dir, "dren.qcv")
        self._populate(vc)
        vc.rename("/docs", "/papers")  # slash-less, as FUSE passes it
        assert vc.get_entry("/docs/") is None
        assert vc.get_entry("/docs/a.txt") is None
        assert vc.get_entry("/papers/") is not None
        assert vc.read_file("/papers/a.txt") == b"alpha"
        assert vc.read_file("/papers/sub/b.txt") == b"beta"

    def test_container_rename_dir_persists_across_reopen(self, tmp_dir):
        path, key, vc = self._open(tmp_dir, "drenp.qcv")
        self._populate(vc)
        vc.save()
        vc.rename("/docs", "/papers")
        vc.save()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.get_entry("/docs/") is None
        assert vc2.get_entry("/docs/sub/b.txt") is None
        assert vc2.read_file("/papers/a.txt") == b"alpha"
        assert vc2.read_file("/papers/sub/b.txt") == b"beta"

    def test_container_rename_dir_slash_suffixed_key(self, tmp_dir):
        path, key, vc = self._open(tmp_dir, "drens.qcv")
        self._populate(vc)
        vc.rename("/docs/", "/papers/")
        assert vc.read_file("/papers/a.txt") == b"alpha"

    def test_container_rename_dir_refusals(self, tmp_dir):
        path, key, vc = self._open(tmp_dir, "drenr.qcv")
        self._populate(vc)
        vc.mkdir("/existing")
        vc.write_file("/afile.txt", b"x")
        with pytest.raises(FileExistsError) as ei:
            vc.rename("/docs", "/existing")
        assert ei.value.errno == errno.EEXIST
        with pytest.raises(NotADirectoryError) as ei:
            vc.rename("/docs", "/afile.txt")
        assert ei.value.errno == errno.ENOTDIR
        with pytest.raises(OSError) as ei:
            vc.rename("/docs", "/docs/inner")
        assert ei.value.errno == errno.EINVAL
        # Unchanged after refusals
        assert vc.read_file("/docs/a.txt") == b"alpha"

    def test_fuse_rename_dir_moves_children_and_buffers(self, tmp_dir):
        path, key, vc = self._open(tmp_dir, "drenf.qcv")
        fs = QuantaCryptFUSE(vc)
        fs.mkdir("/docs", 0o755)
        fd = fs.create("/docs/a.txt", 0o100644)
        fs.write("/docs/a.txt", b"flushed", 0, fd)
        fs.flush("/docs/a.txt", fd)
        # Leave a second, dirty-but-unflushed file to prove buffer re-key
        fd2 = fs.create("/docs/dirty.txt", 0o100644)
        fs.write("/docs/dirty.txt", b"pending", 0, fd2)

        fs.rename("/docs", "/papers")

        assert "a.txt" in fs.readdir("/papers")
        with pytest.raises(OSError) as ei:
            fs.getattr("/docs")
        assert ei.value.errno == errno.ENOENT
        # Dirty buffer moved with the directory; flush persists at new path
        assert "/papers/dirty.txt" in fs._dirty_files
        assert "/docs/dirty.txt" not in fs._file_buffers
        fs.flush("/papers/dirty.txt", fd2)
        fs.release("/papers/dirty.txt", fd2)
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.read_file("/papers/dirty.txt") == b"pending"
        assert vc2.read_file("/papers/a.txt") == b"flushed"

    def test_fuse_rename_dir_with_pending_unlink_child_refuses(self, tmp_dir):
        path, key, vc = self._open(tmp_dir, "drenu.qcv")
        fs = QuantaCryptFUSE(vc)
        fs.mkdir("/docs", 0o755)
        fd = fs.create("/docs/open.txt", 0o100644)
        fs.write("/docs/open.txt", b"held", 0, fd)
        fs.flush("/docs/open.txt", fd)
        fs.unlink("/docs/open.txt")  # deferred: fd still open
        with pytest.raises(OSError) as ei:
            fs.rename("/docs", "/papers")
        assert ei.value.errno == errno.EBUSY
        fs.release("/docs/open.txt", fd)
        fs.rename("/docs", "/papers")  # succeeds once the fd is closed


class TestRenameOntoPendingUnlink:
    """F-005: rename onto a path in _pending_unlink must refuse (EBUSY) —
    letting it land makes the renamed file invisible, drops its writes,
    and deletes it when the unlinked file's last fd closes."""

    def _fs(self, tmp_dir):
        path = os.path.join(tmp_dir, "rpul.qcv")
        meta = vol.create_volume_single(path, "rpul-pw-testpad")
        key = vol.derive_volume_key_single("rpul-pw-testpad", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        return path, key, QuantaCryptFUSE(vc)

    def test_rename_onto_pending_unlink_dest_refuses(self, tmp_dir):
        path, key, fs = self._fs(tmp_dir)
        fd_b = fs.create("/b.txt", 0o100644)
        fs.write("/b.txt", b"doomed", 0, fd_b)
        fs.flush("/b.txt", fd_b)
        fd_a = fs.create("/a.txt", 0o100644)
        fs.write("/a.txt", b"live data", 0, fd_a)
        fs.flush("/a.txt", fd_a)
        fs.release("/a.txt", fd_a)

        fs.unlink("/b.txt")  # deferred: fd_b still open
        with pytest.raises(OSError) as ei:
            fs.rename("/a.txt", "/b.txt")
        assert ei.value.errno == errno.EBUSY
        # Source untouched by the refusal
        assert fs.getattr("/a.txt")["st_size"] == len(b"live data")

        # Once the old fd closes the rename proceeds and the file survives
        fs.release("/b.txt", fd_b)
        fs.rename("/a.txt", "/b.txt")
        fd = fs.open("/b.txt", os.O_RDONLY)
        assert fs.read("/b.txt", 100, 0, fd) == b"live data"
        fs.release("/b.txt", fd)


class TestUnmountResultChecking:
    """F-007: a failed OS unmount must keep the volume tracked (emergency
    save + double-mount guard both depend on tracking) and surface the
    tool's stderr."""

    def test_failed_unmount_keeps_tracking_and_raises(self, tmp_dir):
        path = os.path.join(tmp_dir, "ufail.qcv")
        meta = vol.create_volume_single(path, "ufail-pw")
        key = vol.derive_volume_key_single("ufail-pw", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        mp = os.path.join(tmp_dir, "ufmnt")
        _mounted_volumes[mp] = {
            "volume_path": path, "volume": vc, "thread": None, "fuse": None,
        }
        try:
            with _patched_unmount_subprocess(returncode=1,
                                             stderr="Resource busy"):
                with pytest.raises(RuntimeError, match="Resource busy"):
                    unmount_volume(mp)
            assert mp in _mounted_volumes, \
                "failed unmount must not drop tracking (two-writer hazard)"
        finally:
            _mounted_volumes.pop(mp, None)


class TestFuseLockReentrancy:
    """F-017: the FUSE ops lock must be reentrant — a SIGTERM handler
    running _emergency_save_all on the main thread while that thread
    already holds the lock (unmount → save_all_dirty) would otherwise
    self-deadlock."""

    def test_save_all_dirty_reentrant_under_held_lock(self, tmp_dir):
        path = os.path.join(tmp_dir, "rlock.qcv")
        meta = vol.create_volume_single(path, "rlock-pw")
        key = vol.derive_volume_key_single("rlock-pw", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        fs = QuantaCryptFUSE(vc)
        fd = fs.create("/f.txt", 0o100644)
        fs.write("/f.txt", b"data", 0, fd)
        with fs._lock:  # simulate signal arriving inside a locked section
            fs.save_all_dirty()  # deadlocks in <10ms with a plain Lock
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.read_file("/f.txt") == b"data"


class TestReadFileRange:
    """F-009: read_file_range decrypts only the chunks covering the range
    and must agree byte-for-byte with read_file."""

    def _volume_with_file(self, tmp_dir, data, name="range.qcv"):
        path = os.path.join(tmp_dir, name)
        meta = vol.create_volume_single(path, "range-pw")
        key = vol.derive_volume_key_single("range-pw", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/big.bin", data)
        vc.save()
        return path, key, vc

    def test_ranges_match_full_read(self, tmp_dir):
        cs = vol.VOLUME_CHUNK_SIZE
        data = bytes((i * 31 + 7) % 251 for i in range(cs * 2 + 12345))
        path, key, vc = self._volume_with_file(tmp_dir, data)
        # Fresh container so the range path reads from disk, not _file_data
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        full = vc2.read_file("/big.bin", verify_hash=True)
        assert full == data
        cases = [
            (0, 10),                      # start of chunk 0
            (cs - 5, 10),                 # crosses chunk 0→1 boundary
            (cs, cs),                     # exactly chunk 1
            (cs + 17, cs + 100),          # unaligned, crosses 1→2
            (len(data) - 7, 100),         # runs past EOF → truncated
            (0, len(data)),               # whole file
        ]
        for off, size in cases:
            assert vc2.read_file_range("/big.bin", off, size) == \
                data[off:off + size], f"range mismatch at {off}+{size}"
        assert vc2.read_file_range("/big.bin", len(data), 10) == b""
        assert vc2.read_file_range("/big.bin", len(data) + 99, 1) == b""
        assert vc2.read_file_range("/big.bin", 0, 0) == b""

    def test_range_from_pending_write_buffer(self, tmp_dir):
        # Unsaved writes live in _file_data; ranges must read them too.
        cs = vol.VOLUME_CHUNK_SIZE
        data = os.urandom(cs + 500)
        path = os.path.join(tmp_dir, "rangemem.qcv")
        meta = vol.create_volume_single(path, "range-pw")
        key = vol.derive_volume_key_single("range-pw", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.write_file("/mem.bin", data)  # NOT saved
        assert vc.read_file_range("/mem.bin", cs - 3, 10) == data[cs - 3:cs + 7]

    def test_empty_file_range(self, tmp_dir):
        path, key, vc = self._volume_with_file(tmp_dir, b"", "rempty.qcv")
        assert vc.read_file_range("/big.bin", 0, 100) == b""

    def test_negative_args_raise(self, tmp_dir):
        path, key, vc = self._volume_with_file(tmp_dir, b"abc", "rneg.qcv")
        with pytest.raises(ValueError):
            vc.read_file_range("/big.bin", -1, 10)
        with pytest.raises(ValueError):
            vc.read_file_range("/big.bin", 0, -1)

    def test_missing_and_dir_errno(self, tmp_dir):
        path, key, vc = self._volume_with_file(tmp_dir, b"abc", "rerr.qcv")
        vc.mkdir("/d")
        with pytest.raises(FileNotFoundError) as ei:
            vc.read_file_range("/nope.bin", 0, 1)
        assert ei.value.errno == errno.ENOENT
        with pytest.raises(IsADirectoryError) as ei:
            vc.read_file_range("/d/", 0, 1)
        assert ei.value.errno == errno.EISDIR

    def test_corrupt_chunk_detected_only_when_read(self, tmp_dir):
        cs = vol.VOLUME_CHUNK_SIZE
        data = os.urandom(cs * 2 + 100)
        path, key, vc = self._volume_with_file(tmp_dir, data, "rcorrupt.qcv")
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        entry = vc2.get_entry("/big.bin")
        stride = 8 + cs + 16
        # Flip a ciphertext byte inside chunk 1
        abs_off = vc2._data_offset + entry["data_offset"] + stride + 8 + 50
        with open(path, "r+b") as f:
            f.seek(abs_off)
            b = f.read(1)
            f.seek(abs_off)
            f.write(bytes([b[0] ^ 0xFF]))
        # Chunk 0 still reads fine; chunk 1 fails authentication
        assert vc2.read_file_range("/big.bin", 0, 100) == data[:100]
        with pytest.raises(ValueError, match="Authentication failed"):
            vc2.read_file_range("/big.bin", cs + 10, 10)

    def test_fuse_read_cross_chunk_without_buffer(self, tmp_dir):
        cs = vol.VOLUME_CHUNK_SIZE
        data = os.urandom(cs + 2048)
        path, key, vc = self._volume_with_file(tmp_dir, data, "rfuse.qcv")
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        fs = QuantaCryptFUSE(vc2)
        fd = fs.open("/big.bin", os.O_RDONLY)
        assert fs.read("/big.bin", 4096, cs - 1000, fd) == \
            data[cs - 1000:cs - 1000 + 4096]
        assert "/big.bin" not in fs._file_buffers, \
            "read-only access must not materialize the whole plaintext"
        fs.release("/big.bin", fd)

    def test_fuse_first_write_materializes_existing_content(self, tmp_dir):
        # open() no longer eagerly loads; the first write must, or bytes
        # outside the written range would be zeroed.
        data = b"0123456789abcdef"
        path, key, vc = self._volume_with_file(tmp_dir, data, "rwmat.qcv")
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        fs = QuantaCryptFUSE(vc2)
        fd = fs.open("/big.bin", os.O_RDWR)
        fs.write("/big.bin", b"XY", 4, fd)
        fs.flush("/big.bin", fd)
        fs.release("/big.bin", fd)
        vc3 = vol.VolumeContainer(path, key)
        vc3.open()
        assert vc3.read_file("/big.bin") == b"0123XY6789abcdef"


# ── Run-3 regression tests ──────────────────────────────────────────────────
# See the "Run 3 addendum" in docs/design/review-2026-09-medium-fixes.md.

class TestSelfRename:
    """R3 F-002: rename(x, x) on a file must be a POSIX no-op, not a
    delete-then-crash."""

    def _open(self, tmp_dir, name):
        path = os.path.join(tmp_dir, name)
        meta = vol.create_volume_single(path, "self-pw-testpad")
        key = vol.derive_volume_key_single("self-pw-testpad", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        return path, key, vc

    def test_self_rename_baseline_file_is_noop(self, tmp_dir):
        path, key, vc = self._open(tmp_dir, "selfb.qcv")
        vc.write_file("/keep.txt", b"precious")
        vc.save()
        pending_before = len(vc._pending_ops)
        vc.rename("/keep.txt", "/keep.txt")  # must not raise
        assert len(vc._pending_ops) == pending_before, \
            "self-rename must not queue any journal op"
        assert vc.read_file("/keep.txt") == b"precious"
        vc.save()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.read_file("/keep.txt") == b"precious"

    def test_self_rename_in_session_write_is_noop(self, tmp_dir):
        path, key, vc = self._open(tmp_dir, "selfs.qcv")
        vc.write_file("/fresh.txt", b"unsaved")
        vc.rename("/fresh.txt", "/fresh.txt")
        assert vc.read_file("/fresh.txt") == b"unsaved"
        vc.save()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.read_file("/fresh.txt") == b"unsaved"

    def test_self_rename_dir_is_noop(self, tmp_dir):
        path, key, vc = self._open(tmp_dir, "selfd.qcv")
        vc.mkdir("/d")
        vc.write_file("/d/x.txt", b"x")
        vc.rename("/d", "/d")
        assert vc.read_file("/d/x.txt") == b"x"


class TestOpenFdRekeyOnRename:
    """R3 F-003: fd→vpath tracking must follow renames — otherwise
    unlink-after-rename of an open file bypasses the deferred-unlink
    machinery and eagerly deletes a live file."""

    def _fs(self, tmp_dir, name):
        path = os.path.join(tmp_dir, name)
        meta = vol.create_volume_single(path, "fdrk-pw-testpad")
        key = vol.derive_volume_key_single("fdrk-pw-testpad", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        return path, key, QuantaCryptFUSE(vc)

    def test_unlink_after_rename_defers_while_fd_open(self, tmp_dir):
        path, key, fs = self._fs(tmp_dir, "fdrk.qcv")
        fd = fs.create("/a.txt", 0o100644)
        fs.write("/a.txt", b"still alive", 0, fd)
        fs.flush("/a.txt", fd)
        fs.rename("/a.txt", "/b.txt")
        fs.unlink("/b.txt")  # fd still open → must DEFER, not delete
        assert "/b.txt" in fs._pending_unlink, \
            "unlink of a renamed-while-open file must defer to last close"
        # The live fd keeps its view until release
        assert fs.read("/b.txt", 100, 0, fd) == b"still alive"
        fs.release("/b.txt", fd)
        # Now the deferred delete ran
        assert fs.volume.get_entry("/b.txt") is None

    def test_second_fd_survives_first_release_after_rename(self, tmp_dir):
        path, key, fs = self._fs(tmp_dir, "fdrk2.qcv")
        fd1 = fs.create("/a.txt", 0o100644)
        fs.write("/a.txt", b"shared view", 0, fd1)
        fs.flush("/a.txt", fd1)
        fd2 = fs.open("/a.txt", os.O_RDONLY)
        fs.rename("/a.txt", "/b.txt")
        fs.release("/b.txt", fd1)
        # fd2 is still open on the renamed file: its buffer must survive
        assert fs.read("/b.txt", 100, 0, fd2) == b"shared view"
        fs.release("/b.txt", fd2)

    def test_dir_rename_rekeys_child_fds(self, tmp_dir):
        path, key, fs = self._fs(tmp_dir, "fdrk3.qcv")
        fs.mkdir("/docs", 0o755)
        fd = fs.create("/docs/f.txt", 0o100644)
        fs.write("/docs/f.txt", b"child", 0, fd)
        fs.flush("/docs/f.txt", fd)
        fs.rename("/docs", "/papers")
        fs.unlink("/papers/f.txt")
        assert "/papers/f.txt" in fs._pending_unlink
        fs.release("/papers/f.txt", fd)
        assert fs.volume.get_entry("/papers/f.txt") is None


class TestFuseImportGuardsOSError:
    """R3 F-007: fusepy raises EnvironmentError (OSError), not ImportError,
    when the package imports but no libfuse backend loads — the guards
    must survive it and report a helpful message."""

    def _with_fuse_import_raising(self, exc):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "fuse":
                raise exc
            return real_import(name, *args, **kwargs)

        return patch("builtins.__import__", side_effect=fake_import)

    def test_check_fuse_available_survives_oserror(self):
        from quantacrypt.core.fuse_ops import check_fuse_available
        with self._with_fuse_import_raising(OSError("Unable to find libfuse")):
            ok, msg = check_fuse_available()
        assert ok is False
        assert "libfuse" in msg and "backend" in msg

    def test_check_fuse_components_survives_oserror(self):
        from quantacrypt.core.fuse_ops import check_fuse_components
        with self._with_fuse_import_raising(OSError("Unable to find libfuse")):
            result = check_fuse_components()
        assert result["fusepy"]["ok"] is False
        assert "backend" in result["fusepy"]["detail"]


# ── Run-4 regression tests ──────────────────────────────────────────────────
# See the "Run 4 addendum" in docs/design/review-2026-09-medium-fixes.md.

class TestFuseSelfRename:
    """R4 F-001: FUSE-layer rename(a, a) must not destroy the unflushed
    write buffer (the container-level guard can't help — the FUSE layer
    mutated its own state first)."""

    def _fs(self, tmp_dir):
        path = os.path.join(tmp_dir, "fself.qcv")
        meta = vol.create_volume_single(path, "fself-pw")
        key = vol.derive_volume_key_single("fself-pw", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        return path, key, QuantaCryptFUSE(vc)

    def test_self_rename_preserves_buffer_and_dirty_flag(self, tmp_dir):
        path, key, fs = self._fs(tmp_dir)
        fd = fs.create("/a.txt", 0o100644)
        fs.write("/a.txt", b"hello world", 0, fd)
        fs.rename("/a.txt", "/a.txt")
        assert fs.read("/a.txt", 100, 0, fd) == b"hello world"
        assert "/a.txt" in fs._dirty_files
        fs.flush("/a.txt", fd)
        fs.release("/a.txt", fd)
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.read_file("/a.txt") == b"hello world"


class TestRenameOntoSlashlessDir:
    """R4 F-007: rename(file → existing dir) with the slash-less
    destination FUSE actually passes must refuse EISDIR — not install
    durable /d + /d/ twin keys."""

    def test_slashless_dir_dest_raises_eisdir(self, tmp_dir):
        path = os.path.join(tmp_dir, "twin.qcv")
        meta = vol.create_volume_single(path, "twin-pw-testpad")
        key = vol.derive_volume_key_single("twin-pw-testpad", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        vc.mkdir("/d")
        vc.write_file("/d/child.txt", b"reachable")
        vc.write_file("/a.txt", b"x")
        with pytest.raises(IsADirectoryError) as ei:
            vc.rename("/a.txt", "/d")
        assert ei.value.errno == errno.EISDIR
        # No twin key was created; the namespace is intact
        assert "/d" not in vc.dir_index
        assert vc.get_entry("/d/") is not None
        assert vc.read_file("/d/child.txt") == b"reachable"
        assert vc.read_file("/a.txt") == b"x"


class TestFailedUnmountKeepsPendingUnlink:
    """R4 F-005: a failed OS unmount leaves the mount serving — the
    pre-unmount save must NOT apply/clear the unlink-limbo set, or a
    later flush resurrects deleted files."""

    def test_pending_unlink_survives_failed_unmount(self, tmp_dir):
        path = os.path.join(tmp_dir, "pu.qcv")
        meta = vol.create_volume_single(path, "pu-pw-testpad")
        key = vol.derive_volume_key_single("pu-pw-testpad", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        fs = QuantaCryptFUSE(vc)
        fd = fs.create("/swap.txt", 0o100644)
        fs.write("/swap.txt", b"scratch", 0, fd)
        fs.flush("/swap.txt", fd)
        fs.unlink("/swap.txt")  # deferred: fd still open
        assert "/swap.txt" in fs._pending_unlink

        mp = os.path.join(tmp_dir, "pumnt")
        _mounted_volumes[mp] = {
            "volume_path": path, "volume": vc, "thread": None, "fuse": fs,
        }
        try:
            with _patched_unmount_subprocess(returncode=1, stderr="busy"):
                with pytest.raises(RuntimeError):
                    unmount_volume(mp)
            # Mount still live: the limbo state must be intact so the
            # deferred delete still happens on last close.
            assert "/swap.txt" in fs._pending_unlink
            fs.write("/swap.txt", b"more scratch", 0, fd)
            fs.flush("/swap.txt", fd)  # must NOT resurrect
            fs.release("/swap.txt", fd)
            assert fs.volume.get_entry("/swap.txt") is None
            vc2 = vol.VolumeContainer(path, key)
            vc2.open()
            assert vc2.get_entry("/swap.txt") is None, \
                "unlinked-while-open file resurrected after failed unmount"
        finally:
            _mounted_volumes.pop(mp, None)

    def test_successful_unmount_applies_pending_unlinks(self, tmp_dir):
        path = os.path.join(tmp_dir, "pu2.qcv")
        meta = vol.create_volume_single(path, "pu-pw-testpad")
        key = vol.derive_volume_key_single("pu-pw-testpad", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        fs = QuantaCryptFUSE(vc)
        fd = fs.create("/swap.txt", 0o100644)
        fs.write("/swap.txt", b"scratch", 0, fd)
        fs.flush("/swap.txt", fd)
        fs.unlink("/swap.txt")

        mp = os.path.join(tmp_dir, "pu2mnt")
        _mounted_volumes[mp] = {
            "volume_path": path, "volume": vc, "thread": None, "fuse": fs,
        }
        with _patched_unmount_subprocess():
            unmount_volume(mp)
        assert mp not in _mounted_volumes
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.get_entry("/swap.txt") is None


class TestCrossProcessVolumeLock:
    """R4 F-006: a mount holds an flock on the <volume>.lock sidecar so a
    second PROCESS can't become a second writer on the same journal."""

    def test_lock_acquire_and_conflict(self, tmp_dir):
        import fcntl
        from quantacrypt.core.fuse_ops import (
            _acquire_volume_lock, _release_volume_lock, _volume_locks,
        )
        vpath = os.path.join(tmp_dir, "locked.qcv")
        with open(vpath, "wb") as f:
            f.write(b"stub")
        fd = _acquire_volume_lock(vpath)
        try:
            assert os.path.exists(vpath + ".lock")
            # A second holder (simulating another process's attempt on the
            # same file via an independent fd) must fail LOCK_NB.
            fd2 = os.open(vpath + ".lock", os.O_RDWR)
            with pytest.raises(OSError):
                fcntl.flock(fd2, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.close(fd2)
        finally:
            _volume_locks["__test__"] = fd
            _release_volume_lock("__test__")
        # Released: a fresh acquire succeeds
        fd3 = _acquire_volume_lock(vpath)
        os.close(fd3)

    def test_second_acquire_raises_runtime_error(self, tmp_dir):
        from quantacrypt.core.fuse_ops import _acquire_volume_lock
        vpath = os.path.join(tmp_dir, "locked2.qcv")
        with open(vpath, "wb") as f:
            f.write(b"stub")
        fd = _acquire_volume_lock(vpath)
        try:
            with pytest.raises(RuntimeError,
                               match="mounted by another process"):
                _acquire_volume_lock(vpath)
        finally:
            os.close(fd)


# ── Run-5 regression tests ──────────────────────────────────────────────────
# See the "Run 5 addendum" in docs/design/review-2026-09-medium-fixes.md.

class TestVolumeLockCanonicalization:
    """R5 F-004: aliased paths to the same volume must contend for the
    SAME lock file."""

    def test_symlink_alias_contends_on_same_lock(self, tmp_dir):
        from quantacrypt.core.fuse_ops import _acquire_volume_lock
        vpath = os.path.join(tmp_dir, "canon.qcv")
        with open(vpath, "wb") as f:
            f.write(b"stub")
        alias = os.path.join(tmp_dir, "alias.qcv")
        os.symlink(vpath, alias)
        fd = _acquire_volume_lock(vpath)
        try:
            with pytest.raises(RuntimeError,
                               match="mounted by another process"):
                _acquire_volume_lock(alias)
        finally:
            os.close(fd)


class TestDeadMountReaping:
    """R5 F-007: a mount whose FUSE worker exited (external eject) must be
    reaped — tracking dropped, flock released — instead of blocking every
    remount until app restart."""

    def _dead_thread(self):
        import threading
        t = threading.Thread(target=lambda: None)
        t.start()
        t.join()
        return t

    def test_get_mounted_volumes_reaps_dead_entries(self, tmp_dir):
        from quantacrypt.core.fuse_ops import (
            _acquire_volume_lock, _volume_locks, get_mounted_volumes,
        )
        path = os.path.join(tmp_dir, "reap.qcv")
        meta = vol.create_volume_single(path, "reap-pw-testpad")
        key = vol.derive_volume_key_single("reap-pw-testpad", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        mp = os.path.join(tmp_dir, "reapmnt")
        _mounted_volumes[mp] = {
            "volume_path": path, "volume": vc,
            "thread": self._dead_thread(), "fuse": None,
        }
        _volume_locks[mp] = _acquire_volume_lock(path)
        try:
            mounted = get_mounted_volumes()
            assert mp not in mounted, "dead mount must be reaped"
            assert mp not in _mounted_volumes
            assert mp not in _volume_locks
            # The flock is free again — a remount can proceed
            fd = _acquire_volume_lock(path)
            os.close(fd)
        finally:
            _mounted_volumes.pop(mp, None)

    def test_live_and_injected_entries_survive_reaping(self, tmp_dir):
        from quantacrypt.core.fuse_ops import get_mounted_volumes
        path = os.path.join(tmp_dir, "keep.qcv")
        meta = vol.create_volume_single(path, "keep-pw-testpad")
        key = vol.derive_volume_key_single("keep-pw-testpad", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        mp = os.path.join(tmp_dir, "keepmnt")
        # thread None = direct API / test injection: liveness unknowable,
        # must be left alone
        _mounted_volumes[mp] = {
            "volume_path": path, "volume": vc, "thread": None, "fuse": None,
        }
        try:
            assert mp in get_mounted_volumes()
        finally:
            _mounted_volumes.pop(mp, None)


class TestUnmountCleanupNotStranded:
    """R5 F-007 (R2 refinement): apply_pending_unlinks() failing after a
    successful OS unmount must not strand tracking + flock."""

    def test_tracking_dropped_even_if_unlink_apply_fails(self, tmp_dir):
        from unittest.mock import MagicMock
        path = os.path.join(tmp_dir, "strand.qcv")
        meta = vol.create_volume_single(path, "strand-pw")
        key = vol.derive_volume_key_single("strand-pw", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        fs = QuantaCryptFUSE(vc)
        fs.apply_pending_unlinks = MagicMock(
            side_effect=OSError("disk full"))
        mp = os.path.join(tmp_dir, "strandmnt")
        _mounted_volumes[mp] = {
            "volume_path": path, "volume": vc, "thread": None, "fuse": fs,
        }
        try:
            with _patched_unmount_subprocess():
                # Run 17: the post-unmount persistence failure is logged, not
                # raised — the OS unmount already succeeded and a retry would
                # find no mount to act on.
                unmount_volume(mp)
            assert mp not in _mounted_volumes, \
                "cleanup failure must not strand a torn-down mount"
        finally:
            _mounted_volumes.pop(mp, None)


# ── Run-8 regression test ───────────────────────────────────────────────────

class TestStatfsHostFreeSpace:
    """R8 F-001: statfs must report the HOST filesystem's free space —
    the old max(container, 1 GB) − plaintext formula collapsed to ~zero
    free once a volume held ≈1 GB, and Finder then refused all copies."""

    def _fs(self, tmp_dir):
        path = os.path.join(tmp_dir, "sfs.qcv")
        meta = vol.create_volume_single(path, "sfs-pw-testpad")
        key = vol.derive_volume_key_single("sfs-pw-testpad", meta)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        return QuantaCryptFUSE(vc)

    def test_free_space_tracks_host_not_container(self, tmp_dir):
        """Free space follows the host, full stop.

        R11 briefly folded the write path's per-file memory ceiling into this
        number; run 12 F-003 showed that turned a volume on a 274 GB disk
        into a 2 GB drive. The ceiling now lives in write() as EFBIG, where
        it is true, so this is back to asserting the host value.
        """
        fs = self._fs(tmp_dir)
        st = fs.statfs("/")
        host = os.statvfs(tmp_dir)
        host_free = host.f_bavail * host.f_frsize
        reported_free = st["f_bavail"] * st["f_frsize"]
        # Within 5% of the live host value (disk churns between calls)
        assert abs(reported_free - host_free) < max(host_free * 0.05, 1 << 26)
        assert st["f_blocks"] >= st["f_bavail"]

    def test_large_volume_does_not_collapse_to_zero_free(self, tmp_dir, monkeypatch):
        fs = self._fs(tmp_dir)
        # Simulate a volume already holding 2 GB of plaintext
        monkeypatch.setattr(fs.volume, "stat", lambda: {
            "container_size": 2 << 30, "total_plaintext_size": 2 << 30,
            "file_count": 10, "dir_count": 1,
        })
        st = fs.statfs("/")
        free_bytes = st["f_bavail"] * st["f_frsize"]
        assert free_bytes > 1 << 30, \
            "a large volume must not advertise a full disk"


class TestFlushSkipsUnchangedContent:
    """F-012: an fsync/flush that leaves the bytes identical to the stored
    content must not re-encrypt and re-append the whole file."""

    @pytest.fixture
    def fuse_fs(self, tmp_dir):
        path = os.path.join(tmp_dir, "skip.qcv")
        meta = vol.create_volume_single(path, "pw-testpad")
        vc = vol.VolumeContainer(path, vol.derive_volume_key_single("pw-testpad", meta))
        vc.open()
        return QuantaCryptFUSE(vc)

    def test_identical_rewrite_does_not_touch_container(self, fuse_fs, monkeypatch):
        fs = fuse_fs
        fs.create("/a.txt", 0o644)
        fs.write("/a.txt", b"hello world", 0, 0)
        fs.flush("/a.txt", 0)
        calls = []
        real = fs.volume.write_file
        monkeypatch.setattr(fs.volume, "write_file",
                            lambda v, d, **kw: (calls.append(v), real(v, d, **kw)))
        # Same bytes written again (an editor re-saving, rsync --fsync)
        fs.write("/a.txt", b"hello world", 0, 0)
        fs.fsync("/a.txt", 0, 0)
        assert calls == []
        # A real change still lands
        fs.write("/a.txt", b"HELLO world", 0, 0)
        fs.fsync("/a.txt", 0, 0)
        assert calls == ["/a.txt"]
        assert fs.read("/a.txt", 64, 0, 0) == b"HELLO world"
        assert fs.volume.read_file("/a.txt") == b"HELLO world"
