"""Behaviour pinned by the 2026-09 performance / memory / storage / security
audit (docs/design/audit-2026-09.md).

Every test here drives the real code: containers are written and read back,
tampering is done to the bytes on disk, failures are injected where the
audit injected them.  Nothing asserts on source text.
"""

from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import struct
import zipfile
import zlib

import pytest

from quantacrypt.core import crypto as cc
from quantacrypt.core import fuse_ops as fo
from quantacrypt.core import package as pkg
from quantacrypt.core import volume as vol
from quantacrypt.core.errors import InvalidInput
from tests.conftest import fusepy_backend

PW = "audit-password-2026"
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "v1")


def _creds():
    with open(os.path.join(FIXTURES, "credentials.json"), encoding="utf-8") as f:
        return json.load(f)


def _rewrite_meta(path, mutate):
    """Rewrite a .qcx's cleartext envelope with *mutate* applied to meta."""
    data = bytearray(open(path, "rb").read())
    i = data.rfind(cc.MAGIC)
    n = struct.unpack(">I", data[i + 6:i + 10])[0]
    doc = json.loads(data[i + 10:i + 10 + n])
    mutate(doc["meta"])
    blob = json.dumps(doc, separators=(",", ":")).encode()
    with open(path, "wb") as f:
        f.write(bytes(data[:i]) + cc.MAGIC + len(blob).to_bytes(4, "big") + blob)


# ═══════════════════════════════════════════════════════════════════════════
# Format 1 / journal-era containers keep opening (real fixtures, shipped KDF)
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.real_argon2
class TestLegacyFixturesStillOpen:
    """The fixtures were written by the previous build with the shipped
    Argon2id parameters: format-1 .qcx (Kyber-768, whole-file SHA-256,
    narrow HMAC) and format-2 .qcv (Kyber-768, no kem/argon2 fields)."""

    def test_format_1_password_file_decrypts(self, tmp_path):
        c = _creds()
        meta = pkg.load_pkg(os.path.join(FIXTURES, "single.qcx"))["meta"]
        assert meta["version"] == 1 and "kem" not in meta and "argon2" not in meta
        out = pkg.decrypt_qcx(os.path.join(FIXTURES, "single.qcx"), str(tmp_path),
                              password=c["password"])
        assert hashlib.sha256(open(out["output"], "rb").read()).hexdigest() == c["plaintext_sha256"]

    def test_format_1_split_key_file_decrypts_with_the_old_shares(self, tmp_path):
        c = _creds()
        out = pkg.decrypt_qcx(os.path.join(FIXTURES, "shamir.qcx"), str(tmp_path),
                              shares=c["qcx_shares"][:2])
        assert hashlib.sha256(open(out["output"], "rb").read()).hexdigest() == c["plaintext_sha256"]

    def test_format_1_wrong_password_is_still_a_wrong_password(self, tmp_path):
        with pytest.raises(Exception) as exc:
            pkg.decrypt_qcx(os.path.join(FIXTURES, "single.qcx"), str(tmp_path),
                            password="not-the-password", verify_only=True)
        assert "InvalidTag" in type(exc.value).__name__ or "authentication" in str(exc.value).lower()

    @pytest.mark.parametrize("name", ["single.qcv", "single-compacted.qcv"])
    def test_journal_era_password_volume_opens(self, name, tmp_path):
        c = _creds()
        path = str(tmp_path / name)
        with open(os.path.join(FIXTURES, name), "rb") as src, open(path, "wb") as dst:
            dst.write(src.read())
        header, auth = vol.read_volume_auth_params(path)
        assert header["version"] == 2 and "kem" not in auth and "argon2" not in auth
        key = vol.derive_volume_key_single(c["password"], auth)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        assert vc.read_file("/docs/hello.txt") == b"hello from a v2 volume\n" * 100
        # A compact keeps it at version 2 — nothing it writes needs a newer
        # reader, and the Kyber-era build can still open the result.
        vc.write_file("/new.txt", b"written by the ML-KEM build")
        vc.compact()
        assert vol.read_volume_auth_params(path)[0]["version"] == 2
        vc2 = vol.VolumeContainer(path, vol.derive_volume_key_single(c["password"], auth))
        vc2.open()
        assert vc2.read_file("/new.txt") == b"written by the ML-KEM build"

    def test_journal_era_split_key_volume_opens(self, tmp_path):
        c = _creds()
        path = str(tmp_path / "shamir.qcv")
        with open(os.path.join(FIXTURES, "shamir.qcv"), "rb") as src, open(path, "wb") as dst:
            dst.write(src.read())
        _, auth = vol.read_volume_auth_params(path)
        key = vol.derive_volume_key_shamir(c["qcv_shares"][:2], auth)
        vc = vol.VolumeContainer(path, key)
        vc.open()
        assert vc.read_file("/docs/hello.txt").startswith(b"hello from a v2 volume")


# ═══════════════════════════════════════════════════════════════════════════
# Format 2 (.qcx) / format 3 (.qcv): ML-KEM-768, recorded parameters, full HMAC
# ═══════════════════════════════════════════════════════════════════════════

class TestKemSelection:
    def test_kyber_and_ml_kem_are_not_interchangeable(self):
        pk, sk = cc.kyber_keygen(cc.KEM_KYBER768)
        ct, ss = cc.kyber_encaps(pk, cc.KEM_KYBER768)
        assert cc.kyber_decaps(sk, ct, cc.KEM_KYBER768) == ss
        assert cc.kyber_decaps(sk, ct, cc.KEM_ML_KEM768) != ss

    def test_new_files_name_ml_kem_768(self, tmp_path):
        src = tmp_path / "f.bin"
        src.write_bytes(b"x" * 100)
        pkg.encrypt_to_qcx(str(src), str(tmp_path / "f.qcx"), mode="password", password=PW)
        meta = pkg.load_pkg(str(tmp_path / "f.qcx"))["meta"]
        assert meta["version"] == 2 and meta["kem"] == "ML-KEM-768"
        assert meta["argon2"] == cc.argon2_params()
        assert "payload_offset" in meta

    def test_new_volumes_name_ml_kem_768(self, tmp_path):
        path = str(tmp_path / "v.qcv")
        vol.create_volume_single(path, PW)
        header, auth = vol.read_volume_auth_params(path)
        assert header["version"] == 3 and auth["kem"] == "ML-KEM-768"
        assert auth["argon2"] == cc.argon2_params()

    def test_an_unknown_kem_is_refused_before_any_derivation(self, tmp_path):
        with pytest.raises(ValueError, match="Unsupported key encapsulation"):
            cc.validate_kem("Kyber1024")
        with pytest.raises(ValueError):
            cc.kyber_decaps(b"", b"", "ML-KEM-1024")

    def test_a_format_2_file_that_names_no_kem_is_a_format_error(self, tmp_path):
        src = tmp_path / "f.bin"
        src.write_bytes(b"x")
        out = str(tmp_path / "f.qcx")
        pkg.encrypt_to_qcx(str(src), out, mode="password", password=PW)
        _rewrite_meta(out, lambda m: m.pop("kem"))
        with pytest.raises(ValueError, match="does not name its key encapsulation"):
            pkg.load_pkg(out)


class TestRecordedArgon2Parameters:
    def test_bounds_are_enforced(self):
        good = {"t": 1, "m": 8192, "p": 1}
        assert cc.validate_argon2_params(good) == good
        for bad in ({"t": 0, "m": 8192, "p": 1}, {"t": 33, "m": 8192, "p": 1},
                    {"t": 1, "m": 7, "p": 1}, {"t": 1, "m": (1 << 20) + 1, "p": 1},
                    {"t": 1, "m": 8192, "p": 0}, {"t": 1, "m": 8192, "p": 17},
                    {"t": True, "m": 8192, "p": 1}, {"t": "4", "m": 8192, "p": 1},
                    {"m": 8192, "p": 1}, [], None, "t=4"):
            with pytest.raises(ValueError):
                cc.validate_argon2_params(bad)

    def test_a_reader_honours_the_recorded_cost(self, tmp_path, monkeypatch):
        src = tmp_path / "f.bin"
        src.write_bytes(b"data")
        out = str(tmp_path / "f.qcx")
        pkg.encrypt_to_qcx(str(src), out, mode="password", password=PW)
        # The shipped cost moves; the file still opens because it says what
        # it was made with.
        monkeypatch.setattr(cc, "ARGON2_TIME_COST", cc.ARGON2_TIME_COST + 1)
        assert pkg.decrypt_qcx(out, str(tmp_path), password=PW, verify_only=True)["verified"]
        assert cc.argon2_params()["t"] == cc.ARGON2_TIME_COST

    def test_a_volume_reader_honours_the_recorded_cost(self, tmp_path, monkeypatch):
        path = str(tmp_path / "v.qcv")
        vol.create_volume_single(path, PW)
        monkeypatch.setattr(cc, "ARGON2_MEMORY_COST", cc.ARGON2_MEMORY_COST * 2)
        _, auth = vol.read_volume_auth_params(path)
        vc = vol.VolumeContainer(path, vol.derive_volume_key_single(PW, auth))
        vc.open()
        assert vc.metadata["argon2"]["m"] == cc.ARGON2_MEMORY_COST // 2

    def test_out_of_range_parameters_in_a_file_are_a_format_error(self, tmp_path):
        src = tmp_path / "f.bin"
        src.write_bytes(b"x")
        out = str(tmp_path / "f.qcx")
        pkg.encrypt_to_qcx(str(src), out, mode="password", password=PW)
        _rewrite_meta(out, lambda m: m["argon2"].__setitem__("m", 1 << 30))
        with pytest.raises(ValueError, match="out of range"):
            pkg.load_pkg(out)


class TestFormat2HmacCoversEverything:
    """Review F-042: mode, threshold, total, chunk_size and payload_offset
    were outside the format-1 HMAC.  Format 2 covers every field but the
    tag, so editing any of them is detected."""

    @pytest.fixture
    def encrypted(self, tmp_path):
        src = tmp_path / "f.bin"
        src.write_bytes(os.urandom(50_000))
        out = str(tmp_path / "f.qcx")
        pkg.encrypt_to_qcx(str(src), out, mode="password", password=PW)
        return out

    @pytest.mark.parametrize("field,value", [
        ("payload_offset", 1), ("chunk_size", 65536), ("key_bits", 256),
        ("kem", "Kyber768"), ("version", 1),
    ])
    def test_editing_a_structural_field_is_detected(self, encrypted, tmp_path, field, value):
        _rewrite_meta(encrypted, lambda m: m.__setitem__(field, value))
        with pytest.raises(Exception) as exc:
            pkg.decrypt_qcx(encrypted, str(tmp_path), password=PW, verify_only=True)
        low = (str(exc.value) or type(exc.value).__name__).lower()
        assert "authentication" in low or "invalidtag" in low or "tamper" in low

    def test_editing_the_mode_is_detected(self, encrypted, tmp_path):
        def to_shamir(m):
            m["mode"] = "shamir"; m["threshold"] = 2; m["total"] = 3
        _rewrite_meta(encrypted, to_shamir)
        with pytest.raises(InvalidInput):
            pkg.decrypt_qcx(encrypted, str(tmp_path), password=PW, verify_only=True)

    def test_a_shamir_file_threshold_is_authenticated(self, tmp_path):
        src = tmp_path / "f.bin"
        src.write_bytes(b"x" * 100)
        out = str(tmp_path / "s.qcx")
        res = pkg.encrypt_to_qcx(str(src), out, mode="shamir", k=3, n=4)
        codes = [s["code"] for s in res["shares"]]
        _rewrite_meta(out, lambda m: m.__setitem__("threshold", 2))
        with pytest.raises(Exception):
            pkg.decrypt_qcx(out, str(tmp_path), shares=codes[:2], verify_only=True)
        _rewrite_meta(out, lambda m: m.__setitem__("threshold", 3))
        assert pkg.decrypt_qcx(out, str(tmp_path), shares=codes[:3], verify_only=True)["verified"]


class TestLoadPkgTypeValidation:
    """The envelope is attacker-controlled cleartext; every field the
    decrypt path does arithmetic on is type-checked, as a format error."""

    def _write(self, path, meta):
        blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
        path.write_bytes(b"\x00" * 8 + cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
        return str(path)

    def _meta(self, **over):
        m = {"version": 2, "mode": "single", "kem": cc.KEM_DEFAULT,
             "argon2": cc.argon2_params(), "payload_chunk_count": 1,
             "payload_offset": 8, "chunk_size": cc.CHUNK_SIZE}
        m.update(over)
        return m

    @pytest.mark.parametrize("over,msg", [
        ({"version": "2"}, "not a number"),
        ({"version": 2.0}, "not a number"),
        ({"version": True}, "not a number"),
        ({"mode": "shamir", "threshold": "2", "total": 3}, "not a number"),
        ({"mode": "shamir", "threshold": 2.5, "total": 3}, "not a number"),
        ({"mode": "shamir", "threshold": 2, "total": [3]}, "not a number"),
        ({"payload_chunk_count": "1"}, "not a valid count"),
        ({"payload_chunk_count": -1}, "not a valid count"),
        ({"payload_offset": None}, "not a valid count"),
        ({"chunk_size": 1.5}, "not a valid count"),
        ({"kem": 7}, "Unsupported key encapsulation"),
        ({"argon2": "fast"}, "not an object"),
    ])
    def test_ill_typed_fields_are_format_errors(self, tmp_path, over, msg):
        path = self._write(tmp_path / "x.qcx", self._meta(**over))
        with pytest.raises(ValueError, match=msg):
            pkg.load_pkg(path)

    def test_pathological_nesting_is_a_format_error(self, tmp_path):
        blob = b'{"meta":' + b"[" * 100_000 + b"]" * 100_000 + b"}"
        p = tmp_path / "deep.qcx"
        p.write_bytes(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
        with pytest.raises(ValueError, match="not valid JSON|not a valid dictionary"):
            pkg.load_pkg(str(p))

    def test_a_non_text_crypto_field_is_a_format_error(self, tmp_path):
        path = self._write(tmp_path / "x.qcx", self._meta(argon_salt=[1, 2, 3]))
        meta = pkg.load_pkg(path)["meta"]
        with pytest.raises(ValueError, match="not text"):
            pkg.derive_final_key(meta, password=PW)


# ═══════════════════════════════════════════════════════════════════════════
# Streaming: the push-model encryptor and the folder path
# ═══════════════════════════════════════════════════════════════════════════

class TestChunkEncryptor:
    @pytest.fixture(autouse=True)
    def small_chunks(self, monkeypatch):
        monkeypatch.setattr(cc, "CHUNK_SIZE", 1000)

    @pytest.mark.parametrize("size", [0, 1, 999, 1000, 1001, 2000, 2001, 5555])
    def test_any_piece_pattern_yields_the_file_stream(self, tmp_path, size):
        """Pushing the same bytes in odd-sized pieces must produce a stream
        that the standard decryptor reads back as the whole plaintext, with
        the same chunk count the path-based encryptor would produce."""
        key = os.urandom(64)
        plain = os.urandom(size)
        src = tmp_path / "p.bin"
        src.write_bytes(plain)
        with open(tmp_path / "ref.bin", "wb") as f:
            ref_nonce, ref_count, ref_written, _ = cc.stream_encrypt_payload(
                str(src), f, key, size, hash_plaintext=False)
        sink = io.BytesIO()
        enc = cc.ChunkEncryptor(sink, key)
        pos, step = 0, 7
        while pos < size:
            enc.write(plain[pos:pos + step]); pos += step; step = (step * 3) % 613 + 1
        assert enc.finish() is None
        assert enc.chunk_count == ref_count
        assert enc.bytes_written == ref_written == len(sink.getvalue())
        assert enc.plain_bytes == size
        out = tmp_path / "ct.bin"
        out.write_bytes(sink.getvalue())
        buf = io.BytesIO()
        cc.stream_decrypt_payload(str(out), buf, key, 0, enc.chunk_count,
                                  enc.base_nonce, hash_plaintext=False)
        assert buf.getvalue() == plain

    def test_a_hash_is_kept_when_asked_for(self):
        sink = io.BytesIO()
        enc = cc.ChunkEncryptor(sink, os.urandom(64), hash_plaintext=True)
        enc.write(b"abc" * 1000)
        assert enc.finish() == hashlib.sha256(b"abc" * 1000).hexdigest()

    def test_write_after_finish_and_double_finish_are_errors(self):
        enc = cc.ChunkEncryptor(io.BytesIO(), os.urandom(64))
        enc.write(b"x")
        enc.finish()
        with pytest.raises(ValueError):
            enc.write(b"y")
        with pytest.raises(ValueError):
            enc.finish()

    def test_cancellation_fires_at_a_chunk_boundary(self):
        enc = cc.ChunkEncryptor(io.BytesIO(), os.urandom(64), cancel_check=lambda: True)
        enc.write(b"x" * 999)                  # nothing sealed yet
        with pytest.raises(cc.CancelledOperation):
            enc.write(b"x" * 2)                # crosses the boundary

    def test_it_is_a_valid_zipfile_sink(self, tmp_path):
        """No seek/tell: zipfile must fall back to data descriptors and the
        archive must still be a normal zip."""
        key = os.urandom(64)
        sink = io.BytesIO()
        enc = cc.ChunkEncryptor(sink, key)
        assert not enc.seekable()
        with zipfile.ZipFile(enc, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("a.txt", b"hello " * 500)
            zf.writestr("b.bin", os.urandom(3000), compress_type=zipfile.ZIP_STORED)
        enc.finish()
        ct = tmp_path / "ct.bin"
        ct.write_bytes(sink.getvalue())
        buf = io.BytesIO()
        cc.stream_decrypt_payload(str(ct), buf, key, 0, enc.chunk_count,
                                  enc.base_nonce, hash_plaintext=False)
        with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
            assert zf.testzip() is None
            assert zf.read("a.txt") == b"hello " * 500


class TestAdaptiveCompression:
    def test_incompressible_members_are_stored_and_text_deflated(self, tmp_path):
        rnd = tmp_path / "r.bin"; rnd.write_bytes(os.urandom(100_000))
        txt = tmp_path / "t.txt"; txt.write_bytes(b"the quick brown fox " * 5000)
        tiny = tmp_path / "s.bin"; tiny.write_bytes(os.urandom(100))
        assert pkg._compress_type(str(rnd)) == zipfile.ZIP_STORED
        assert pkg._compress_type(str(txt)) == zipfile.ZIP_DEFLATED
        assert pkg._compress_type(str(tiny)) == zipfile.ZIP_DEFLATED   # below the sample floor
        assert pkg._compress_type(str(tmp_path / "missing")) == zipfile.ZIP_DEFLATED

    def test_the_sample_is_bounded(self, tmp_path, monkeypatch):
        seen = []
        real = zlib.compress
        monkeypatch.setattr(zlib, "compress", lambda d, lvl=6: seen.append(len(d)) or real(d, lvl))
        big = tmp_path / "big.bin"; big.write_bytes(os.urandom(1 << 20))
        pkg._compress_type(str(big))
        assert seen == [pkg._ZIP_SAMPLE]


class TestFolderEncryptionStreams:
    def test_a_folder_source_reports_its_zip_size_and_skipped_links(self, tmp_path):
        folder = tmp_path / "docs"
        (folder / "sub").mkdir(parents=True)
        (folder / "a.txt").write_bytes(b"a" * 5000)
        os.symlink(str(folder / "a.txt"), str(folder / "link.txt"))
        out = str(tmp_path / "docs.qcx")
        res = pkg.encrypt_to_qcx(str(folder), out, mode="password", password=PW)
        assert res["skipped_symlinks"] == ["link.txt"]
        (tmp_path / "o").mkdir()
        got = pkg.decrypt_qcx(out, str(tmp_path / "o"), password=PW)
        assert got["original_size"] == os.path.getsize(got["output"]) > 0
        with zipfile.ZipFile(got["output"]) as zf:
            assert sorted(zf.namelist()) == ["docs/", "docs/a.txt", "docs/sub/"]

    def test_a_cancel_during_the_folder_walk_leaves_nothing(self, tmp_path):
        folder = tmp_path / "docs"
        folder.mkdir()
        for i in range(20):
            (folder / f"{i}.txt").write_bytes(b"x" * 1000)
        out = tmp_path / "docs.qcx"
        with pytest.raises(cc.CancelledOperation):
            pkg.encrypt_to_qcx(str(folder), str(out), mode="password", password=PW,
                               cancel_check=lambda: True)
        assert sorted(p.name for p in tmp_path.iterdir()) == ["docs"]


# ═══════════════════════════════════════════════════════════════════════════
# Volumes: bounded reads, tamper cross-check, tombstones, compaction, pread
# ═══════════════════════════════════════════════════════════════════════════

def _volume(tmp_path, name="v.qcv"):
    path = str(tmp_path / name)
    meta = vol.create_volume_single(path, PW)
    key = vol.derive_volume_key_single(PW, meta)
    vc = vol.VolumeContainer(path, key)
    vc.open()
    return path, key, vc


class TestPreAuthenticationBounds:
    def test_an_absurd_auth_params_length_is_refused(self, tmp_path):
        path, _, _ = _volume(tmp_path)
        with open(path, "r+b") as f:
            f.seek(vol.HEADER_SIZE)
            f.write(struct.pack(">I", vol._MAX_AUTH_PARAMS + 1))
        with pytest.raises(ValueError, match="implausibly large"):
            vol.read_volume_auth_params(path)

    def test_an_absurd_block_length_is_refused(self, tmp_path):
        path, key, _ = _volume(tmp_path)
        with open(path, "rb") as f:
            f.seek(vol.HEADER_SIZE)
            n = struct.unpack(">I", f.read(4))[0]
            block_at = vol.HEADER_SIZE + 4 + n
        with open(path, "r+b") as f:
            f.seek(block_at)
            f.write(struct.pack(">I", vol._MAX_BLOCK + 1))
        with pytest.raises(ValueError, match="implausibly large"):
            vol.VolumeContainer(path, key).open()

    def test_non_object_auth_params_are_a_format_error(self, tmp_path):
        path, _, _ = _volume(tmp_path)
        payload = b"[1,2,3]"
        with open(path, "r+b") as f:
            f.seek(vol.HEADER_SIZE)
            f.write(struct.pack(">I", len(payload)) + payload)
        with pytest.raises(ValueError, match="not an object"):
            vol.read_volume_auth_params(path)


class TestCleartextAuthParamsAreCrossChecked:
    """Review F-044: everything mount and inspect say before a credential
    exists came from the unauthenticated block.  open() now compares it with
    the sealed copy, so an edit produces a tamper error, not a wrong story."""

    def _rewrite_auth(self, path, mutate):
        with open(path, "rb") as f:
            head = f.read(vol.HEADER_SIZE)
            n = struct.unpack(">I", f.read(4))[0]
            auth = json.loads(f.read(n))
            rest = f.read()
        mutate(auth)
        payload = json.dumps(auth, sort_keys=True, separators=(",", ":")).encode()
        with open(path, "wb") as f:
            f.write(head + struct.pack(">I", len(payload)) + payload + rest)

    def test_editing_the_mode_is_detected(self, tmp_path):
        path, key, _ = _volume(tmp_path)
        self._rewrite_auth(path, lambda a: a.__setitem__("mode", "shamir"))
        with pytest.raises(ValueError, match="tampered"):
            vol.VolumeContainer(path, key).open()

    def test_editing_the_threshold_is_detected(self, tmp_path):
        path = str(tmp_path / "s.qcv")
        _, shares = vol.create_volume_shamir(path, 3, 2)
        _, auth = vol.read_volume_auth_params(path)
        key = vol.derive_volume_key_shamir(shares[:2], auth)
        self._rewrite_auth(path, lambda a: a.__setitem__("threshold", 1))
        with pytest.raises(ValueError, match="tampered"):
            vol.VolumeContainer(path, key).open()

    def test_an_untouched_block_opens(self, tmp_path):
        path, key, _ = _volume(tmp_path)
        vol.VolumeContainer(path, key).open()


class TestTombstonesBeforeAWriteAreDropped:
    def test_the_editor_save_pattern_emits_one_record(self, tmp_path):
        path, key, vc = _volume(tmp_path)
        vc.write_file("/final.txt", b"old" * 1000)
        vc.save()
        vc.write_file("/final.txt.tmp", b"new" * 1000)
        vc.rename("/final.txt.tmp", "/final.txt")
        ops = vc._coalesce_pending_ops()
        assert [(o["type"], o["vpath"]) for o in ops] == [("write", "/final.txt")]

    def test_a_rename_onto_a_deleted_path_keeps_no_tombstone(self, tmp_path):
        path, key, vc = _volume(tmp_path)
        vc.write_file("/a.txt", b"a")
        vc.write_file("/b.txt", b"b")
        vc.save()
        vc.delete("/a.txt")
        vc.rename("/b.txt", "/a.txt")
        types = [(o["type"], o["vpath"]) for o in vc._coalesce_pending_ops()]
        assert ("delete", "/a.txt") not in types
        assert ("rename", "/b.txt") in types

    def test_a_delete_with_no_later_write_survives(self, tmp_path):
        path, key, vc = _volume(tmp_path)
        vc.write_file("/a.txt", b"a")
        vc.save()
        vc.delete("/a.txt")
        assert [(o["type"], o["vpath"]) for o in vc._coalesce_pending_ops()] == [("delete", "/a.txt")]

    def test_disk_full_during_the_replacing_write_keeps_the_old_content(self, tmp_path, monkeypatch):
        """Measured before the fix: ENOSPC while writing the body left the
        complete tombstone durable, and a fresh open showed the file
        missing with nothing suspicious to report."""
        path, key, vc = _volume(tmp_path)
        vc.write_file("/final.txt", b"old" * 1000)
        vc.save()
        vc.write_file("/final.txt.tmp", b"new" * 1000)
        vc.rename("/final.txt.tmp", "/final.txt")
        real = vol._write_journal_record

        def failing(f, k, op, body):
            off = real(f, k, op, body)
            if op["type"] == "write":
                f.flush()
                f.truncate(off + 10)      # the body never made it
                raise OSError(errno.ENOSPC, "No space left on device")
            return off

        monkeypatch.setattr(vol, "_write_journal_record", failing)
        with pytest.raises(OSError):
            vc.save()
        monkeypatch.undo()
        vc2 = vol.VolumeContainer(path, key)
        vc2.open()
        assert vc2.read_file("/final.txt") == b"old" * 1000
        assert vc2.journal_suspicious is False
        # In-session retry then persists the new content.
        vc.save()
        vc3 = vol.VolumeContainer(path, key)
        vc3.open()
        assert vc3.read_file("/final.txt") == b"new" * 1000


class TestCompactionKeepsPermissionsAndReopensTheInode:
    def test_reads_follow_the_container_across_a_compact(self, tmp_path):
        path, key, vc = _volume(tmp_path)
        vc.write_file("/a.bin", os.urandom(200_000))
        vc.save()
        first = vc.read_file("/a.bin")
        vc.write_file("/b.bin", os.urandom(70_000))
        vc.compact()                      # new inode; the read fd must be reopened
        assert vc.read_file("/a.bin") == first
        assert vc.read_file_range("/a.bin", 65_000, 10_000) == first[65_000:75_000]
        vc.close(); vc.close()            # idempotent

    def test_the_dead_space_accounting_matches_reality(self, tmp_path):
        path, key, vc = _volume(tmp_path)
        vc.write_file("/a.bin", b"a" * 100_000)
        vc.save()
        # Only the record header is reclaimable after a fresh write.
        assert vc._dead_and_live_bytes()[0] < 1024
        vc.write_file("/a.bin", b"b" * 100_000)   # the old blob is dead once appended
        dead, live = vc._dead_and_live_bytes()
        assert dead > 100_000 and live > 100_000
        vc.save()
        dead_after, _ = vc._dead_and_live_bytes()
        assert dead <= dead_after <= dead + 1024    # plus one record header
        vc.delete("/a.bin")
        assert vc._dead_and_live_bytes()[1] == 0


class TestLruOversizedPut:
    def test_an_entry_larger_than_the_cache_is_not_inserted(self):
        c = fo.LRUCache(max_bytes=100)
        c.put("a", b"x" * 60)
        c.put("big", b"y" * 101)
        assert c.get("big") is None
        assert c.get("a") == b"x" * 60      # the others were not evicted for it
        assert c.size == 60


class TestMountPointMustBeEmpty:
    def test_a_populated_directory_is_refused(self, tmp_path, monkeypatch):
        fusepy = fusepy_backend()
        path, key, _ = _volume(tmp_path)
        monkeypatch.setattr(fusepy, "FUSE", lambda *a, **kw: None)
        mp = tmp_path / "mnt"
        mp.mkdir()
        (mp / "precious.txt").write_text("would be hidden under the mount")
        with pytest.raises(ValueError, match="not empty"):
            fo.mount_volume(path, key, str(mp), foreground=True)
        assert (mp / "precious.txt").exists()

    def test_an_empty_or_missing_directory_is_fine(self, tmp_path, monkeypatch):
        fusepy = fusepy_backend()
        path, key, _ = _volume(tmp_path)
        monkeypatch.setattr(fusepy, "FUSE", lambda *a, **kw: None)
        fo.mount_volume(path, key, str(tmp_path / "fresh"), foreground=True)
        (tmp_path / "empty").mkdir()
        fo.mount_volume(path, key, str(tmp_path / "empty"), foreground=True)


class TestMnemonicShareValidation:
    def test_an_index_of_zero_is_refused(self):
        words = cc.share_to_mnemonic({"index": 0, "value": 12345, "modulus": cc.SHAMIR_PRIME})
        with pytest.raises(ValueError, match="index out of range"):
            cc.mnemonic_to_share(words)

    def test_a_value_at_the_modulus_is_refused(self):
        words = cc.share_to_mnemonic({"index": 1, "value": cc.SHAMIR_PRIME, "modulus": cc.SHAMIR_PRIME})
        with pytest.raises(ValueError, match="value out of range"):
            cc.mnemonic_to_share(words)

    def test_a_real_share_round_trips(self):
        share = cc.shamir_split(os.urandom(64), 3, 2)[0]
        assert cc.mnemonic_to_share(cc.share_to_mnemonic(share))["value"] == share["value"]
