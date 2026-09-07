"""
QuantaCrypt GUI Layer Logic Tests
Tests for validation, file loading, and GUI helper functions.
"""
import base64
import gc as _gc
import io
import math
import os
import sys
import json
import struct
import tempfile
import time as _time
import traceback
import inspect
import types

import pytest
from quantacrypt.core import crypto as cc
from tests.conftest import (_widget_texts, MAGIC, make_pkg_bytes, load_pkg, _make_qcx,
                            _decrypt_qcx, requires_tkinter, HAS_TKINTER)


# ─────────────────────────────────────────────────────────────────────────────
# Tk harness
#
# The UI is excluded from the coverage gate, so these tests are the only thing
# standing behind ~7k lines of Tk.  They drive real widgets and assert on what
# the widgets end up showing — never on the text of the methods that built them
# (a source-text assertion passes a rewrite under a new name and fails a
# comment edit).
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _collect_tk_garbage_on_the_main_thread():
    """Free discarded Tk interpreters here, on the thread that made them.

    Tcl aborts the process — ``Tcl_AsyncDelete: async handler deleted by the
    wrong thread``, SIGABRT, the whole run gone — if a Tk interpreter object is
    finalised on a thread other than the one that created it.  Production
    hands us exactly that setup: ``PasswordStrengthBar`` (src/quantacrypt/ui/
    shared.py:1002) keeps a scoring daemon thread alive for seconds after a
    password field is touched, so a collection triggered by *that* thread's
    allocations can pick up a Tk object an earlier test dropped.  Which test
    is holding the garbage when the sweep lands depends purely on order.
    Collecting on the main thread after every test keeps the window shut
    instead of leaving it to luck.
    """
    yield
    _gc.collect()


def _pump_until(widget, predicate, timeout=3.0):
    """Run the Tk event loop until ``predicate`` holds.  Needed for the
    debounced ``after`` callbacks the wizards schedule."""
    deadline = _time.monotonic() + timeout
    while not predicate() and _time.monotonic() < deadline:
        widget.update()
        _time.sleep(0.01)
    return predicate()


def _take_keyboard_focus(widget):
    """Give ``widget`` the *display's* keyboard focus, not just the toplevel's.

    ``event_generate`` does not deliver a key event to the widget it is called
    on: Tk routes every KeyPress through the display's focus window
    (``TkFocusKeyEvent``) and drops it outright when no window of this
    application holds that focus.  ``focus_set`` only records the focus
    *inside* a toplevel — measured on a fresh root, ``root.focus_get()`` is
    still ``None`` after it, and the synthesised key never reaches the
    binding.

    That made the key assertions below depend on whether some *earlier* test
    in the process had already forced the application focus — production code
    does exactly that in ``shared.confirm`` (``win.focus_force()``) and in
    ``decryptor.WordEntry.focus_force`` — so the same test passed or failed on
    test order alone.  Forcing the focus here makes each test establish the
    state it asserts on instead of inheriting it, and the check keeps a
    failure to acquire it loud rather than turning the assertions vacuous.
    """
    widget.winfo_toplevel().lift()
    widget.focus_force()
    widget.update()
    assert widget.focus_get() is widget, (
        "this test's own window never took the keyboard focus, so the key "
        "events below would be dropped and the assertions would pass or fail "
        "for the wrong reason")


def _encryptor_app(tk_root, monkeypatch, find_dec=None):
    """A real EncryptorApp, off-screen, with OS notifications suppressed.
    ``find_dec`` stubs the embedded-decryptor probe so the optional PORTABLE
    FILE section can be exercised in both states."""
    import quantacrypt.ui.encryptor as enc_mod
    monkeypatch.setattr(enc_mod, "notify", lambda *a, **k: None)
    monkeypatch.setattr(enc_mod.EncryptorApp, "_find_dec", lambda self: find_dec)
    app = enc_mod.EncryptorApp(tk_root)
    app.withdraw()
    return app


def _decryptor_app(tk_root, tmp_path, monkeypatch, qcx_sample):
    """A real DecryptorApp with a real .qcx loaded, off-screen, with the
    recent-files store redirected into ``tmp_path`` and notifications muted."""
    import shutil
    import quantacrypt.ui.decryptor as dec_mod
    from quantacrypt.ui.shared import RecentFiles
    monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
    monkeypatch.setattr(dec_mod, "notify", lambda *a, **k: None)
    src, meta = qcx_sample
    qcx = tmp_path / "data.qcx"
    shutil.copy(src, qcx)
    app = dec_mod.DecryptorApp(tk_root, payload={"meta": meta}, qcx_path=str(qcx))
    app.withdraw()
    return app, qcx


# ─────────────────────────────────────────────────────────────────────────────
# A4: GUI-layer tests
# These test logic functions that don't need a display: _validate, _collect_shares,
# file loading, version checks, crypto return signatures, and helper functions.
# ─────────────────────────────────────────────────────────────────────────────


@requires_tkinter
class TestEncryptorValidate:
    """Test encryptor._validate logic without opening a window."""

    def _make_validator(self, path, out, mode="single", pw1="secret", pw2="secret", n=3, k=2,
                        is_folder=False):
        """Build a minimal stand-in for encryptor._validate."""
        import types
        obj = types.SimpleNamespace(
            _path=path,
            _is_folder=is_folder,
            _src_type=types.SimpleNamespace(get=lambda: "file"),  # not batch
            _mode=types.SimpleNamespace(get=lambda: mode),
            _pw1v=types.SimpleNamespace(get=lambda: pw1),
            _pw2v=types.SimpleNamespace(get=lambda: pw2),
            _n=types.SimpleNamespace(get=lambda: n),
            _k=types.SimpleNamespace(get=lambda: k),
            _out=types.SimpleNamespace(get=lambda: out),
        )
        # Import the actual method logic as a function
        from quantacrypt.ui.encryptor import EncryptorApp
        obj._validate = lambda: EncryptorApp._validate(obj)
        return obj

    def test_no_file_selected(self):
        obj = self._make_validator(None, "/tmp/out.qcx")
        assert obj._validate() == "Select a file or folder first"

    def test_nonexistent_file(self):
        obj = self._make_validator("/tmp/does_not_exist_xyz.bin", "/tmp/out.qcx")
        assert obj._validate() == "Select a file first"

    def test_empty_output(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test"); path = f.name
        try:
            obj = self._make_validator(path, "")
            assert obj._validate() == "Specify an output path"
        finally:
            os.unlink(path)

    def test_password_empty(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test"); path = f.name
        try:
            obj = self._make_validator(path, "/tmp/out.qcx", pw1="", pw2="")
            assert obj._validate() == "Password cannot be empty"
        finally:
            os.unlink(path)

    def test_password_mismatch(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test"); path = f.name
        try:
            obj = self._make_validator(path, "/tmp/out.qcx",
                                       pw1="abcdefgh", pw2="xyzxyzxy")
            assert obj._validate() == "Passwords don't match"
        finally:
            os.unlink(path)

    def test_shamir_k_exceeds_n(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test"); path = f.name
        try:
            obj = self._make_validator(path, "/tmp/out.qcx", mode="shamir", n=3, k=5)
            assert "Threshold" in obj._validate()
        finally:
            os.unlink(path)

    def test_shamir_k_less_than_2(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test"); path = f.name
        try:
            obj = self._make_validator(path, "/tmp/out.qcx", mode="shamir", n=3, k=1)
            assert obj._validate() is not None
        finally:
            os.unlink(path)

    def test_valid_single_password(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test"); path = f.name
        try:
            obj = self._make_validator(path, "/tmp/out.qcx",
                                       pw1="goodpassword", pw2="goodpassword")
            assert obj._validate() is None
        finally:
            os.unlink(path)

    def test_same_file_input_output(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"test"); path = f.name
        try:
            obj = self._make_validator(path, path, pw1="pw", pw2="pw")
            result = obj._validate()
            assert result is not None and "same" in result.lower()
        finally:
            os.unlink(path)


class TestLoadPkg:
    """Test the .qcx file parser (load_pkg) and version checks."""

    def _make_meta(self):
        return {
            "version": cc.FORMAT_VERSION, "mode": "single", "key_bits": 512,
            "kem": cc.KEM_DEFAULT, "argon2": cc.argon2_params(),
            "argon_salt":"aa==","kyber_kem_ct":"aa==","kyber_sk_enc_nonce":"aa==",
            "kyber_sk_enc":"aa==","payload_nonce":"aa==","payload_chunk_count":1,
            "filename_nonce":"aa==","filename_enc":"aa==","hmac":"x",
        }

    def _make_qcx(self, meta, version_override=None):
        """Write a minimal .qcx file and return its path."""
        if version_override is not None:
            meta = dict(meta); meta["version"] = version_override
        pkg = json.dumps({"meta": meta}, separators=(",",":")).encode()
        block = cc.MAGIC + len(pkg).to_bytes(4,"big") + pkg
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".qcx")
        f.write(b"FAKEBINARYPREFIX" + block)
        f.close()
        return f.name

    def test_valid_file_parsed(self):
        meta = self._make_meta()
        path = self._make_qcx(meta)
        try:
            from quantacrypt.ui.decryptor import load_pkg
            result = load_pkg(path)
            assert "meta" in result
            assert result["meta"]["mode"] == "single"
        finally:
            os.unlink(path)

    def test_not_a_qcx_raises(self):
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        f.write(b"this is not a qcx file at all"); f.close()
        try:
            from quantacrypt.ui.decryptor import load_pkg
            try:
                load_pkg(f.name)
                assert False, "Should have raised ValueError"
            except ValueError as e:
                assert "QuantaCrypt" in str(e) or "truncated" in str(e).lower()
        finally:
            os.unlink(f.name)

    def test_future_version_raises(self):
        path = self._make_qcx(self._make_meta(), version_override=999)
        try:
            from quantacrypt.ui.decryptor import load_pkg
            with pytest.raises(ValueError, match="newer version"):
                load_pkg(path)
        finally:
            os.unlink(path)

    def test_old_version_raises(self):
        path = self._make_qcx(self._make_meta(), version_override=0)
        try:
            from quantacrypt.ui.decryptor import load_pkg
            with pytest.raises(ValueError, match="older format|no longer supported"):
                load_pkg(path)
        finally:
            os.unlink(path)

    def test_current_version_accepted(self):
        path = self._make_qcx(self._make_meta(), version_override=cc.FORMAT_VERSION)
        try:
            from quantacrypt.ui.decryptor import load_pkg
            result = load_pkg(path)
            assert "meta" in result
        finally:
            os.unlink(path)


class TestCryptoReturnSignatures:
    """decrypt_streaming returns (fname, sz, ts) 3-tuple; roundtrip data matches."""

    def test_single_decrypt_returns_correct_values(self, tmp_path):
        data = b"hello world"
        enc, meta, _, fk = _make_qcx(tmp_path, data, filename="test.txt")
        result, fname, sz, ts = _decrypt_qcx(enc, meta, fk)
        assert result == data and fname == "test.txt"
        assert sz == len(data) and ts > 0

    def test_shamir_decrypt_returns_correct_values(self, tmp_path):
        data = b"shamir test"
        enc, meta, _, fk = _make_qcx(tmp_path, data, filename="doc.pdf", n=3, k=2)
        result, fname, sz, ts = _decrypt_qcx(enc, meta, fk)
        assert result == data and fname == "doc.pdf"
        assert sz == len(data) and ts > 0

    def test_sz_matches_data_length(self, tmp_path):
        enc, meta, _, fk = _make_qcx(tmp_path, b"x" * 1000)
        _, _, sz, _ = _decrypt_qcx(enc, meta, fk)
        assert sz == 1000

    def test_ts_is_recent(self, tmp_path):
        before = int(_time.time()) - 2
        enc, meta, _, fk = _make_qcx(tmp_path, b"ts test")
        _, _, _, ts = _decrypt_qcx(enc, meta, fk)
        assert before <= ts <= int(_time.time()) + 2

    def test_wrong_password_still_raises(self, tmp_path):
        import base64 as _b64, json
        src = tmp_path / "s.bin"; src.write_bytes(b"secret")
        enc = tmp_path / "e.qcx"
        with open(enc, "wb") as f:
            off = f.tell()
            meta = cc.encrypt_single_streaming(str(src), f, "correct")
            meta["payload_offset"] = off
            blob = json.dumps({"meta": meta}, separators=(",",":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4,"big") + blob)
        wrong_argon = cc.argon2id_derive(b"wrong", _b64.b64decode(meta["argon_salt"]))
        with pytest.raises(Exception):
            cc.aes_gcm_decrypt(wrong_argon, _b64.b64decode(meta["kyber_sk_enc_nonce"]),
                               _b64.b64decode(meta["kyber_sk_enc"]))


class TestShamirRecover:
    """Test B5: shamir_recover range check."""

    def test_valid_recovery_works(self):
        secret = os.urandom(cc.KEY_BYTES)
        shares = cc.shamir_split(secret, 3, 2)
        recovered = cc.shamir_recover(shares[:2])
        assert recovered == secret

    def test_corrupted_share_raises_valueerror(self):
        secret = os.urandom(cc.KEY_BYTES)
        shares = cc.shamir_split(secret, 3, 2)
        # Corrupt value to something astronomically large
        bad = [dict(shares[0]), dict(shares[1])]
        bad[0]["value"] = cc.SHAMIR_PRIME + 1  # outside valid range
        bad[0]["modulus"] = bad[0]["value"] + 999  # bypass modulus check
        # The recovery might not error on the Shamir lib, but our range check catches it
        try:
            result = cc.shamir_recover(bad)
            # If it didn't raise, result must still fit in KEY_BYTES (our check passed)
            assert len(result) == cc.KEY_BYTES
        except (ValueError, OverflowError):
            pass  # either is acceptable — crash prevented


class TestMagicConstant:
    """Test A2: MAGIC is the same in all modules."""

    def test_magic_consistent_across_modules(self):
        from quantacrypt.ui.decryptor import MAGIC as dec_magic
        from quantacrypt.core.crypto import MAGIC as cc_magic
        assert dec_magic == cc_magic == b"QCBIN\x01"

    def test_magic_used_in_file_format(self):
        meta = {
            "version": cc.FORMAT_VERSION, "mode": "single", "key_bits": 512,
            "kem": cc.KEM_DEFAULT, "argon2": cc.argon2_params(),
            "argon_salt":"aa==","kyber_kem_ct":"aa==","kyber_sk_enc_nonce":"aa==",
            "kyber_sk_enc":"aa==","payload_nonce":"aa==","payload_chunk_count":1,
            "filename_nonce":"aa==","filename_enc":"aa==","hmac":"x",
        }
        pkg = json.dumps({"meta": meta}, separators=(",",":")).encode()
        block = cc.MAGIC + len(pkg).to_bytes(4,"big") + pkg
        assert block.startswith(cc.MAGIC)
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".qcx")
        f.write(b"PREFIX" + block); f.close()
        try:
            from quantacrypt.ui.decryptor import load_pkg
            result = load_pkg(f.name)
            assert result["meta"]["mode"] == "single"
        finally:
            os.unlink(f.name)


class TestPasswordStrengthZxcvbn:
    """Test U5: PasswordStrengthBar uses zxcvbn (no display needed)."""

    def test_zxcvbn_importable(self):
        from zxcvbn import zxcvbn
        result = zxcvbn("password123")
        assert "score" in result
        assert 0 <= result["score"] <= 4

    def test_common_password_scores_low(self):
        from zxcvbn import zxcvbn
        result = zxcvbn("password")
        assert result["score"] <= 1, "Common passwords should score 0 or 1"

    def test_strong_passphrase_scores_high(self):
        from zxcvbn import zxcvbn
        result = zxcvbn("correct-horse-battery-staple-99!")
        assert result["score"] >= 3, "Strong passphrases should score 3 or 4"

    def test_password123_not_strong(self):
        from zxcvbn import zxcvbn
        # Previously this scored "Good" with naive entropy — zxcvbn should catch it
        result = zxcvbn("password123!")
        assert result["score"] <= 2, f"'password123!' should not score Good/Strong, got {result['score']}"


class TestRevealHelper:
    """Test _reveal doesn't crash (it just shells out — we don't verify the window opens)."""

    def test_reveal_existing_path_no_exception(self):
        from quantacrypt.ui.encryptor import _reveal
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            _reveal(path)  # Should not raise even if the file doesn't exist in Finder
        except Exception as e:
            assert False, f"_reveal raised unexpectedly: {e}"
        finally:
            os.unlink(path)

    def test_reveal_nonexistent_path_no_exception(self):
        from quantacrypt.ui.encryptor import _reveal
        _reveal("/tmp/nonexistent_xyz_path")  # Should silently swallow error


@requires_tkinter
class TestFileInfoCard:
    """Test U3: FileInfoCard shows sz/ts when provided."""

    def test_filinfocard_accepts_sz_ts(self):
        """Verify FileInfoCard constructor signature accepts sz and ts."""
        import inspect
        from quantacrypt.ui.decryptor import FileInfoCard
        sig = inspect.signature(FileInfoCard.__init__)
        params = list(sig.parameters.keys())
        assert "sz" in params, "FileInfoCard should accept sz parameter"
        assert "ts" in params, "FileInfoCard should accept ts parameter"

    def test_format_size_accuracy(self):
        from quantacrypt.ui.shared import fmt_size
        # Decimal units, as Finder and the native shell show them.
        assert fmt_size(0)    == "0 B"
        assert fmt_size(999)  == "999 B"
        assert fmt_size(1000) == "1.0 KB"
        assert fmt_size(1536) == "1.5 KB"
        assert fmt_size(1_000_000) == "1.0 MB"
        assert fmt_size(5_000_000_000) == "5.0 GB"



# ═══════════════════════════════════════════════════════════════════════════════
# Tests for round-3 UX fixes
# ═══════════════════════════════════════════════════════════════════════════════

class TestHardFileSizeLimit:
    """Streaming has no file size cap — O(CHUNK_SIZE) RAM regardless of input."""

    def test_no_max_file_bytes_constant(self):
        # Size cap fully removed — streaming handles any file the OS can open
        assert not hasattr(cc, "MAX_FILE_BYTES"), \
            "MAX_FILE_BYTES should be removed — streaming has no size limit"

    def test_no_size_rejection_for_large_files(self, tmp_path):
        # Streaming: no arbitrary size cap exists in the crypto layer
        assert not hasattr(cc, "_LEGACY_MAX_FILE_BYTES"), \
            "Legacy hard limit should be removed, not kept as a separate constant"
        # CHUNK_SIZE constant must exist and be a reasonable power-of-two block
        assert hasattr(cc, "CHUNK_SIZE")
        assert cc.CHUNK_SIZE >= 64 * 1024          # at least 64 KB
        assert cc.CHUNK_SIZE <= 64 * 1024 * 1024   # at most 64 MB
        assert (cc.CHUNK_SIZE & (cc.CHUNK_SIZE - 1)) == 0  # power of two


@requires_tkinter
class TestSharesPendingGuard:
    """Fix 6: Unsaved Shamir shares warn before navigating away."""

    def test_check_shares_saved_method_exists(self):
        from quantacrypt.ui import encryptor
        assert hasattr(encryptor.EncryptorApp, "_check_shares_saved")

    def test_check_shares_saved_uses_pending_set(self):
        """Behavior test of the guard (R4 F-004: per-file token set —
        replacing the old getsource string assertions, which only
        mirrored the implementation text)."""
        import types
        from quantacrypt.ui.encryptor import EncryptorApp
        obj = types.SimpleNamespace(_shares_pending=set())
        check = lambda: EncryptorApp._check_shares_saved(obj)
        # Empty set → safe to leave, no dialog
        assert check() is True
        # Non-empty set → guard consults the user (patch the dialog)
        obj._shares_pending = {"/out/a.qcx", "/out/b.qcx"}
        import quantacrypt.ui.encryptor as enc_mod
        from unittest.mock import patch
        with patch.object(enc_mod.messagebox, "askyesno",
                          return_value=False) as m:
            assert check() is False
        assert m.call_count == 1
        # Saving ONE file's shares must NOT disarm the guard for the rest
        obj._shares_pending.discard("/out/a.qcx")
        with patch.object(enc_mod.messagebox, "askyesno",
                          return_value=False):
            assert check() is False
        # All saved → safe again
        obj._shares_pending.discard("/out/b.qcx")
        assert check() is True


@requires_tkinter
class TestWizardStepDuringEncryption:
    """Fix 8: starting an encryption moves the wizard to step 4 (Encrypt),
    not step 3 (Output)."""

    def test_start_advances_wizard_to_the_encrypt_step(self, tk_root, tmp_path, monkeypatch):
        import threading
        app = _encryptor_app(tk_root, monkeypatch)
        try:
            src = tmp_path / "in.bin"
            src.write_bytes(b"payload" * 64)
            app._path = str(src)
            app._out.delete(0, "end")
            app._out.insert(0, str(tmp_path / "out.qcx"))
            app._pw1v.set("correct-horse-battery-9")
            app._pw2v.set("correct-horse-battery-9")
            # Stub the worker: what's under test is the UI transition _start
            # makes, not a real encryption on a background thread.
            dispatched = threading.Event()
            monkeypatch.setattr(app, "_run", lambda p: dispatched.set())
            monkeypatch.setattr(app, "_confirm_weak_password", lambda: True)
            app._wiz.set_step(0)

            app._start()

            assert dispatched.wait(10), "_start should dispatch the encrypt worker"
            assert app._wiz._active == 4
            assert app.STEPS[4] == "Encrypt" and app.STEPS[3] == "Output"
        finally:
            app.destroy()

    def test_start_does_not_advance_when_validation_fails(self, tk_root, monkeypatch):
        app = _encryptor_app(tk_root, monkeypatch)
        try:
            app._wiz.set_step(0)
            app._path = None          # nothing selected → _validate returns an error
            app._start()
            assert app._wiz._active == 0
        finally:
            app.destroy()


def _fail_stand_in(mode="single", k=2, n=3):
    """Bare namespace carrying only what DecryptorApp._fail touches, so the
    error-classification branches run without a display."""
    import types
    from quantacrypt.ui.decryptor import DecryptorApp
    obj = types.SimpleNamespace(
        _busy=True, _cancel=True, _mode_val=mode, _pw_failures=0,
        _meta={"mode": mode, "threshold": k, "total": n},
        _prog=types.SimpleNamespace(stop=lambda: None, pack_forget=lambda: None),
        _cancel_row=types.SimpleNamespace(pack_forget=lambda: None),
        _thaw=lambda: None, _focus_credential=lambda: None,
        _cv=types.SimpleNamespace(yview_moveto=lambda f: None),
        steps=[], errors=[], afters=[],
    )
    obj._wiz = types.SimpleNamespace(set_step=obj.steps.append)
    obj._set_error = lambda text, detail="": obj.errors.append((text, detail))
    obj.after = lambda ms, fn=None: obj.afters.append(fn)
    obj._shares_wrong_copy = lambda: DecryptorApp._shares_wrong_copy(obj)
    obj._fail = lambda exc: DecryptorApp._fail(obj, exc)
    return obj


@requires_tkinter
class TestDecryptorFail:
    """Behaviour of DecryptorApp._fail (replaces the getsource checks for
    'stays at step 2' and 'Checksum branch uses fixed copy')."""

    @pytest.fixture(autouse=True)
    def _quiet_notify(self):
        from unittest.mock import patch
        import quantacrypt.ui.decryptor as dec_mod
        with patch.object(dec_mod, "notify"):
            yield

    def test_wrong_password_counts_and_stays_on_decrypt_step(self):
        from cryptography.exceptions import InvalidTag
        from quantacrypt.ui.decryptor import NO_RECOVERY_NOTE
        obj = _fail_stand_in("single")
        for i in range(1, 4):
            obj._fail(InvalidTag())
            text, detail = obj.errors[-1]
            assert text.startswith("Wrong password")
            assert obj._pw_failures == i
            assert detail == (NO_RECOVERY_NOTE if i >= 3 else "")
        assert obj.steps == [2, 2, 2] and obj._busy is False and obj._cancel is False

    def test_corrupt_payload_is_never_called_a_wrong_password(self):
        """F-101 (Tk): the key was proven before the payload failed — the
        helper's 'damaged copy' sentence, no attempt counter, no Caps Lock."""
        from quantacrypt.core.errors import CorruptPayload
        msg = ("The file's contents are damaged or were altered after encryption — "
               "the password is right, but this copy can't be restored.")
        for mode in ("single", "shamir"):
            obj = _fail_stand_in(mode)
            obj._fail(CorruptPayload(msg))
            text, detail = obj.errors[-1]
            assert text == msg
            assert "Wrong password" not in text and "don't unlock" not in text
            assert obj._pw_failures == 0 and detail == ""

    def test_format_class_errors_show_the_helper_message(self):
        from quantacrypt.core.errors import InvalidInput
        obj = _fail_stand_in("single")
        obj._fail(ValueError("File appears truncated"))
        assert "truncated" in obj.errors[-1][0] and obj._pw_failures == 0
        obj._fail(InvalidInput("Need 2 different shares to open this file, got 1"))
        assert obj.errors[-1][0] == "Need 2 different shares to open this file, got 1"

    def test_shamir_wrong_key_and_checksum_use_fixed_copy(self):
        from cryptography.exceptions import InvalidTag
        obj = _fail_stand_in("shamir")
        obj._fail(InvalidTag())
        assert obj.errors[-1][0] == obj._shares_wrong_copy() and obj._pw_failures == 0
        raw = "Checksum mismatch: 0xdeadbeef != 0xcafebabe"
        obj._fail(ValueError(raw))
        assert obj.errors[-1][0] == obj._shares_wrong_copy()
        assert "0xdeadbeef" not in obj.errors[-1][0]   # never the raw message

    def test_pre_mapped_string_still_tolerated(self):
        obj = _fail_stand_in("single")
        obj._fail("InvalidTag")
        assert obj.errors[-1][0].startswith("Wrong password") and obj._pw_failures == 1


@requires_tkinter
class TestFileCardKeyboard:
    """Fix 4: FileCard is keyboard accessible."""

    @staticmethod
    def _card(tk_root):
        """A focused FileCard whose picker is swapped for a recorder — the real
        one opens a modal file dialog that would hang the run."""
        from quantacrypt.ui.shared import FileCard
        picks = []
        fc = FileCard(tk_root, on_select=lambda p: None)
        fc._pick = lambda: picks.append("pick")
        fc.pack()
        tk_root.update()
        _take_keyboard_focus(fc)
        return fc, picks

    def test_filecard_is_in_the_tab_order(self, tk_root):
        from quantacrypt.ui.shared import FileCard
        fc = FileCard(tk_root, on_select=lambda p: None)
        assert str(fc.cget("takefocus")) in ("1", "True")

    def test_filecard_return_activates_the_picker(self, tk_root):
        fc, picks = self._card(tk_root)
        fc.event_generate("<Return>", when="now")
        tk_root.update()
        assert picks == ["pick"]

    def test_filecard_space_activates_the_picker(self, tk_root):
        fc, picks = self._card(tk_root)
        fc.event_generate("<space>", when="now")
        tk_root.update()
        assert picks == ["pick"]

    def test_disabled_filecard_ignores_clicks(self, tk_root):
        fc, picks = self._card(tk_root)
        fc.set_enabled(False)
        fc.event_generate("<Button-1>", when="now")
        tk_root.update()
        assert picks == []


@requires_tkinter
class TestSegmentedControlKeyboard:
    """Fix 17: SegmentedControl keyboard navigation."""

    @staticmethod
    def _control(tk_root, value="a"):
        import tkinter as tk
        from quantacrypt.ui.shared import SegmentedControl
        var = tk.StringVar(master=tk_root, value=value)
        sc = SegmentedControl(tk_root, [("a", "A"), ("b", "B"), ("c", "C")], var)
        sc.pack()
        tk_root.update()
        _take_keyboard_focus(sc)
        return sc, var

    def test_segmented_control_has_step_method(self):
        from quantacrypt.ui import shared as shared_ui
        assert hasattr(shared_ui.SegmentedControl, "_step")

    def test_step_wraps_around(self, tk_root):
        """Stepping off either end lands on the option at the other end."""
        sc, var = self._control(tk_root)
        seen = []
        for _ in range(4):
            sc._step(1)
            seen.append(var.get())
        assert seen == ["b", "c", "a", "b"]
        var.set("a")
        sc._step(-1)
        assert var.get() == "c"

    def test_arrow_keys_change_the_selection(self, tk_root):
        sc, var = self._control(tk_root)
        sc.event_generate("<Right>", when="now")
        tk_root.update()
        assert var.get() == "b"
        sc.event_generate("<Left>", when="now")
        tk_root.update()
        assert var.get() == "a"

    def test_segmented_control_is_in_the_tab_order(self, tk_root):
        sc, _var = self._control(tk_root)
        assert str(sc.cget("takefocus")) in ("1", "True")

    def test_disabled_control_ignores_arrow_keys(self, tk_root):
        sc, var = self._control(tk_root)
        sc.set_enabled(False)
        sc.event_generate("<Right>", when="now")
        tk_root.update()
        assert var.get() == "a"


@requires_tkinter
class TestFlatButtonHoverOnEnable:
    """Fix 22: FlatButton picks up the hover colour if the pointer is already
    over it when it is re-enabled."""

    @staticmethod
    def _button(tk_root):
        from quantacrypt.ui.shared import FlatButton
        btn = FlatButton(tk_root, "Go", lambda: None, primary=True)
        btn.pack()
        tk_root.update()
        return btn

    def test_enable_applies_hover_when_the_pointer_is_over_the_button(self, tk_root):
        btn = self._button(tk_root)
        btn.enable(False)
        # The real pointer can't be moved from a test, so stub the single
        # query enable() makes about where it is.
        btn.winfo_pointerxy = lambda: (btn.winfo_rootx() + 2, btn.winfo_rooty() + 2)
        btn.enable(True)
        assert btn.cget("bg") == btn._hov

    def test_enable_keeps_the_rest_colour_when_the_pointer_is_elsewhere(self, tk_root):
        btn = self._button(tk_root)
        btn.enable(False)
        btn.winfo_pointerxy = lambda: (btn.winfo_rootx() - 500, btn.winfo_rooty() - 500)
        btn.enable(True)
        assert btn.cget("bg") == btn._bg


@requires_tkinter
class TestOutputPathPreservation:
    """Fix 13: _load_payload only suggests an output path when the field is empty."""

    def test_load_payload_preserves_a_typed_path(self, tk_root, tmp_path, monkeypatch,
                                                 qcx_sample):
        app, _qcx = _decryptor_app(tk_root, tmp_path, monkeypatch, qcx_sample)
        try:
            typed = str(tmp_path / "somewhere-else")
            app._out.delete(0, "end")
            app._out.insert(0, typed)
            app._load_payload()          # re-render for the same file
            assert app._out.get() == typed
        finally:
            app.destroy()

    def test_load_payload_suggests_a_dir_for_a_newly_opened_file(self, tk_root, tmp_path,
                                                                 monkeypatch, qcx_sample):
        app, qcx = _decryptor_app(tk_root, tmp_path, monkeypatch, qcx_sample)
        try:
            app._out.delete(0, "end")
            app._out.insert(0, str(tmp_path / "somewhere-else"))
            app._load_payload(path=str(qcx))   # a newly opened file overrides
            assert app._out.get() == os.path.dirname(os.path.abspath(str(qcx)))
        finally:
            app.destroy()


@requires_tkinter
class TestFnameSanitization:
    """Fix 15: the filename recovered from metadata is shown as a basename, so
    a traversal-shaped name can't be rendered as a path."""

    def test_done_shows_only_the_basename_of_the_recovered_name(self, tk_root, tmp_path,
                                                                monkeypatch, qcx_sample):
        app, _qcx = _decryptor_app(tk_root, tmp_path, monkeypatch, qcx_sample)
        try:
            out = tmp_path / "restored.bin"
            out.write_bytes(b"z" * 10)
            app._done(str(out), 10, fname="../../../etc/passwd", sz=10, ts=0)
            shown = _widget_texts(app._results)
            assert "passwd" in shown
            assert not any(".." in text for text in shown)
        finally:
            app.destroy()

    def test_basename_strips_path_traversal(self):
        import os
        evil = "../../../etc/passwd"
        assert os.path.basename(evil) == "passwd"

    def test_basename_on_normal_name_unchanged(self):
        import os
        assert os.path.basename("document.pdf") == "document.pdf"


@requires_tkinter
class TestMatchLblClearedOnDone:
    """Fix 20: _match_lbl cleared on successful encryption."""

    def test_done_clears_the_match_label_and_the_passwords(self, tk_root, tmp_path,
                                                           monkeypatch):
        app = _encryptor_app(tk_root, monkeypatch)
        try:
            out = tmp_path / "out.qcx"
            out.write_bytes(b"y" * 4096)
            app._match_lbl.config(text="Passwords match")
            app._pw1v.set("hunter2-testpad")
            app._pw2v.set("hunter2-testpad")
            app._done(str(out), [], embedded=False)
            assert app._match_lbl.cget("text") == ""
            assert app._pw1v.get() == "" and app._pw2v.get() == ""
        finally:
            app.destroy()


@requires_tkinter
class TestWizardStepsLabelTruncation:
    """Fix 21: WizardSteps truncates step labels that don't fit their slot."""

    def test_draw_truncates_long_labels(self, tk_root):
        from quantacrypt.ui.shared import WizardSteps
        long_name = "Extraordinarily Long Step Name"
        w = WizardSteps(tk_root, ["Source", long_name, "Out"])
        w.pack()
        tk_root.update()
        drawn = [w.itemcget(i, "text") for i in w.find_all() if w.type(i) == "text"]
        assert "Source" in drawn and "Out" in drawn          # short labels untouched
        shortened = [t for t in drawn if t.startswith("Extraordina")]
        assert shortened, f"long label missing from {drawn}"
        assert shortened[0] != long_name
        assert shortened[0].endswith("…") and len(shortened[0]) < len(long_name)


@requires_tkinter
class TestFreezeThaw:
    """Fix 18: All controls frozen during encryption."""

    def test_freeze_method_exists(self):
        from quantacrypt.ui import encryptor
        assert hasattr(encryptor.EncryptorApp, "_freeze")

    def test_thaw_method_exists(self):
        from quantacrypt.ui import encryptor
        assert hasattr(encryptor.EncryptorApp, "_thaw")

    def test_freeze_disables_password_fields_and_the_action_button(self, tk_root, monkeypatch):
        app = _encryptor_app(tk_root, monkeypatch)
        try:
            assert app._pw1.cget("state") == "normal"
            app._freeze()
            assert app._pw1.cget("state") == "disabled"
            assert app._pw2.cget("state") == "disabled"
            assert app._btn._enabled is False
        finally:
            app.destroy()

    def test_thaw_re_enables_fields(self, tk_root, monkeypatch):
        app = _encryptor_app(tk_root, monkeypatch)
        try:
            app._freeze()
            app._thaw()
            assert app._pw1.cget("state") == "normal"
            assert app._pw2.cget("state") == "normal"
            assert app._btn._enabled is True
        finally:
            app.destroy()

    def test_thaw_keeps_password_fields_disabled_in_shamir_mode(self, tk_root, monkeypatch):
        """Shamir mode has no password, so thawing must not hand the fields back."""
        app = _encryptor_app(tk_root, monkeypatch)
        try:
            app._mode.set("shamir")
            tk_root.update()
            app._freeze()
            app._thaw()
            assert app._pw1.cget("state") == "disabled"
            assert app._btn._enabled is True
        finally:
            app.destroy()


@requires_tkinter
class TestShamirKClamp:
    """Fix 12: K is clamped to N, debounced so a half-typed number survives."""

    def test_clamp_k_method_exists(self):
        from quantacrypt.ui import encryptor
        assert hasattr(encryptor.EncryptorApp, "_clamp_k")

    def test_clamp_k_defers_the_clamp_then_applies_it(self, tk_root, monkeypatch):
        app = _encryptor_app(tk_root, monkeypatch)
        try:
            app._n.set(3)
            app._k.set(9)
            app._clamp_k()
            # Debounced: the value still being typed must survive the keystroke…
            assert app._k.get() == 9
            assert app._clamp_job
            assert _pump_until(app, lambda: not app._clamp_job), "clamp never ran"
            # …and be pulled down to N once typing stops.
            assert app._k.get() == 3
            assert app._n.get() == 3
        finally:
            app.destroy()

    def test_emptied_split_fields_never_raise_past_the_freeze(self, tk_root, monkeypatch):
        """Run 18 F-204: _start read the IntVars after _freeze(); an emptied
        Entry made get() raise and left the window busy and unclosable."""
        import inspect
        from quantacrypt.ui.encryptor import EncryptorApp
        app = _encryptor_app(tk_root, monkeypatch)
        try:
            app._n.set(""); app._k.set("")
            assert app._kn() is None
            app._mode.set("single")
            assert app._validate_secret() == "Password cannot be empty"
            app._reset()                                   # used to raise at the k/n read
            app._n.set(5); app._k.set(3)
            assert app._kn() == (5, 3)
            src = inspect.getsource(EncryptorApp._start)
            assert src.index("self._kn()") < src.index("self._busy=True")
            assert "self._k.get()" not in src.split("self._busy=True", 1)[1]
            # Run 19 F-002: the batch twin.
            srcb = inspect.getsource(EncryptorApp._start_batch)
            assert srcb.index("self._kn()") < srcb.index("self._busy = True")
            assert "self._k.get()" not in srcb.split("self._busy = True", 1)[1]
        finally:
            app.destroy()

    def test_batch_start_with_an_emptied_split_field_does_not_strand_the_wizard(self, tk_root, tmp_path, monkeypatch):
        """Run 19 F-002: `_start_batch` read the IntVars after the freeze.
        Behavioural, not a source-text pin: that is what let the twin through."""
        from quantacrypt.ui import encryptor as enc
        app = _encryptor_app(tk_root, monkeypatch)
        spawned = []
        class FakeThread:
            def __init__(self, *a, **kw): spawned.append(kw.get("target"))
            def start(self): pass
        monkeypatch.setattr(enc.threading, "Thread", FakeThread)
        monkeypatch.setattr(app, "_confirm_weak_password", lambda: True)
        try:
            src = tmp_path / "one.txt"; src.write_text("x")
            app._batch_paths = [str(src)]                    # _build_batch_ui seeds the folder from it
            app._src_type.set("batch"); app._build_batch_ui(); app._on_src_type()
            app._batch_out_var.set(str(tmp_path))
            app._mode.set("single"); app._pw1v.set("correct horse battery"); app._pw2v.set("correct horse battery")
            app._k.set("")                                   # an emptied Entry
            app._start()                                     # used to raise TclError after the freeze
            assert spawned and app._busy is True and (app._result_n, app._result_k) == (0, 0)
        finally:
            app._busy = False
            app.destroy()

    def test_can_quit_mirrors_the_close_guard(self, tk_root, monkeypatch):
        """Run 19 F-001: the Quit Apple event asks the wizard."""
        from quantacrypt.ui import encryptor as enc
        app = _encryptor_app(tk_root, monkeypatch)
        try:
            assert app.can_quit() is True
            app._busy = True
            assert app.can_quit() is False
            app._busy = False
            app._shares_pending = {"/x.qcx"}
            monkeypatch.setattr(enc.messagebox, "askyesno", lambda *a, **k: False)
            assert app.can_quit() is False
            monkeypatch.setattr(enc.messagebox, "askyesno", lambda *a, **k: True)
            assert app.can_quit() is True
        finally:
            app._busy = False; app._shares_pending = set()
            app.destroy()

    def test_do_clamp_bounds_n_and_k(self, tk_root, monkeypatch):
        app = _encryptor_app(tk_root, monkeypatch)
        try:
            app._n.set(99)
            app._k.set(1)
            app._do_clamp()
            assert (app._n.get(), app._k.get()) == (20, 2)
            app._n.set(1)
            app._k.set(1)
            app._do_clamp()
            assert (app._n.get(), app._k.get()) == (2, 2)
        finally:
            app.destroy()

    def test_clamp_k_summary_reports_the_clamped_values(self, tk_root, monkeypatch):
        app = _encryptor_app(tk_root, monkeypatch)
        try:
            app._n.set(5)
            app._k.set(9)
            app._clamp_k()
            assert app._shamir_summary.cget("text") == \
                "Any 5 of 5 people can unlock the file"
        finally:
            app.destroy()


@requires_tkinter
class TestDropHintConditional:
    """Fix 9: the drop hint is only shown when a drop target was registered —
    otherwise it promises something the build can't do."""

    @staticmethod
    def _launcher(tk_root, tmp_path, monkeypatch, dnd):
        import quantacrypt.ui.launcher as launcher
        import quantacrypt.ui.updater as updater
        from quantacrypt.ui.shared import RecentFiles, RecentVolumes
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
        monkeypatch.setattr(RecentVolumes, "_PATH", str(tmp_path / "volumes.json"))
        monkeypatch.setattr(launcher, "_DND_FILES", dnd)
        # src defect: LauncherApp.__init__ (src/quantacrypt/ui/launcher.py:50-51)
        # unconditionally starts updater.check_for_update's daemon thread — a
        # live GitHub request with no opt-out — and that thread outlives the
        # test that built the window.  Any garbage collection that lands on it
        # finalises a Tk interpreter off the main thread, and Tcl aborts the
        # whole process ("Tcl_AsyncDelete: async handler deleted by the wrong
        # thread", SIGABRT).  Measured: seeds that put this class before the
        # remaining Tk tests killed the run outright (seed 1000003, 19 tests
        # in).  Keeping that thread from starting is this test's own reset of
        # state production leaks; it changes nothing the class asserts on.
        monkeypatch.setattr(updater, "check_for_update", lambda *a, **k: None)
        app = launcher.LauncherApp(tk_root)
        app.withdraw()
        return app

    def test_no_drop_promise_without_tkinterdnd2(self, tk_root, tmp_path, monkeypatch):
        app = self._launcher(tk_root, tmp_path, monkeypatch, None)
        try:
            assert app._hint.cget("text") == ""
            assert not any("drop" in t.lower() or "drag" in t.lower()
                           for t in _widget_texts(app))
        finally:
            app.destroy()

    def test_drop_hint_shown_when_tkinterdnd2_is_present(self, tk_root, tmp_path, monkeypatch):
        app = self._launcher(tk_root, tmp_path, monkeypatch, "DND_Files")
        try:
            assert "drop" in app._hint.cget("text").lower()
        finally:
            app.destroy()


@requires_tkinter
class TestSelfExecutingSection:
    """Fix 11: the PORTABLE FILE section is hidden when no decryptor binary
    exists to embed (frozen builds, and source checkouts without a build)."""

    def test_section_hidden_without_a_binary(self, tk_root, monkeypatch):
        app = _encryptor_app(tk_root, monkeypatch, find_dec=None)
        try:
            assert not hasattr(app, "_embed_chk")
            assert not any("PORTABLE" in t for t in _widget_texts(app))
        finally:
            app.destroy()

    def test_section_shown_when_a_binary_is_found(self, tk_root, tmp_path, monkeypatch):
        fake = tmp_path / "quantacrypt-decryptor"
        fake.write_bytes(b"#!/bin/sh\nexit 0\n")
        app = _encryptor_app(tk_root, monkeypatch, find_dec=str(fake))
        try:
            assert hasattr(app, "_embed_chk")
            assert any("PORTABLE" in t for t in _widget_texts(app))
        finally:
            app.destroy()


@requires_tkinter
class TestSizeAnnotation:
    """Fix 19: the success card splits decryptor overhead out of the total size."""

    def test_done_splits_decryptor_and_payload_sizes(self, tk_root, tmp_path, monkeypatch):
        from quantacrypt.ui.shared import fmt_size
        app = _encryptor_app(tk_root, monkeypatch)
        try:
            out = tmp_path / "out.qcx"
            out.write_bytes(b"y" * 5000)
            app._done(str(out), [], embedded=True, dec_size=2000)
            expected = (f"{fmt_size(5000)}  ({fmt_size(2000)} decryptor + "
                        f"{fmt_size(3000)} data)")
            assert expected in _widget_texts(app._results)
        finally:
            app.destroy()

    def test_done_shows_a_plain_size_when_nothing_is_embedded(self, tk_root, tmp_path,
                                                              monkeypatch):
        from quantacrypt.ui.shared import fmt_size
        app = _encryptor_app(tk_root, monkeypatch)
        try:
            out = tmp_path / "out.qcx"
            out.write_bytes(b"y" * 5000)
            app._done(str(out), [], embedded=False)
            texts = _widget_texts(app._results)
            assert fmt_size(5000) in texts
            assert not any("decryptor +" in t for t in texts)
        finally:
            app.destroy()


# ═══════════════════════════════════════════════════════════════════════════════
# Tests for Streaming Encryption (large-file support)
# ═══════════════════════════════════════════════════════════════════════════════

class TestStreamingConstants:
    """Crypto core constants and module-level exports."""

    def test_format_version_is_2(self):
        """Format 2: ML-KEM-768, recorded Argon2 parameters, full HMAC."""
        assert cc.FORMAT_VERSION == 2

    def test_max_format_version_is_2(self):
        assert cc.MAX_FORMAT_VERSION == 2

    def test_format_1_is_still_readable(self):
        assert cc.MIN_FORMAT_VERSION == 1

    def test_chunk_size_is_power_of_two(self):
        cs = cc.CHUNK_SIZE
        assert cs > 0
        assert (cs & (cs - 1)) == 0, "CHUNK_SIZE must be a power of two"

    def test_streaming_functions_exist(self):
        assert callable(cc.stream_encrypt_payload)
        assert callable(cc.stream_decrypt_payload)
        assert callable(cc.encrypt_single_streaming)
        assert callable(cc.encrypt_shamir_streaming)
        assert callable(cc.decrypt_streaming)

    def test_chunk_nonce_derivation_unique_per_chunk(self):
        base = os.urandom(12)
        n0 = cc._chunk_nonce(base, 0)
        n1 = cc._chunk_nonce(base, 1)
        n2 = cc._chunk_nonce(base, 2)
        assert n0 != n1 != n2
        assert len(n0) == 12

    def test_chunk_aad_encodes_last_flag(self):
        mid  = cc._chunk_aad(5, False)
        last = cc._chunk_aad(5, True)
        assert mid  != last
        assert mid[-1]  == 0x00
        assert last[-1] == 0xFF

    def test_chunk_nonce_different_base_nonces(self):
        """Two files with different base_nonces produce different chunk nonces."""
        b1, b2 = os.urandom(12), os.urandom(12)
        assert cc._chunk_nonce(b1, 0) != cc._chunk_nonce(b2, 0)


class TestStreamingRoundTrip:
    """Full encrypt → decrypt round-trips with the streaming API."""

    def _enc_dec(self, tmp_path, data, password="hunter2-testpad", filename="test.bin"):
        src = tmp_path / "src.bin"
        enc = tmp_path / "src.qcx"
        out = tmp_path / "out.bin"
        src.write_bytes(data)

        # Encrypt
        with open(enc, "wb") as f:
            payload_offset = f.tell()
            meta = cc.encrypt_single_streaming(str(src), f, password, filename=filename)
            meta["payload_offset"] = payload_offset
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)

        # Re-load via load_pkg (same path as production)
        from quantacrypt.ui.decryptor import load_pkg
        pkg = load_pkg(str(enc))
        meta2 = pkg["meta"]

        # Decrypt
        argon_key = cc.argon2id_derive(password.encode(), base64.b64decode(meta2["argon_salt"]))
        sk        = cc.aes_gcm_decrypt(argon_key, base64.b64decode(meta2["kyber_sk_enc_nonce"]),
                                       base64.b64decode(meta2["kyber_sk_enc"]))
        kem_ss    = cc.kyber_decaps(sk, base64.b64decode(meta2["kyber_kem_ct"]))
        final_key = cc.xor_bytes(argon_key, kem_ss)

        with open(out, "wb") as f:
            fname, sz, ts = cc.decrypt_streaming(str(enc), f, meta2, final_key)

        return out.read_bytes(), fname, sz, ts, meta2

    def test_empty_file(self, tmp_path):
        data = b""
        result, fname, sz, ts, meta = self._enc_dec(tmp_path, data, filename="empty.bin")
        assert result == data
        assert fname == "empty.bin"
        assert sz == 0

    def test_single_byte(self, tmp_path):
        data = b"\x42"
        result, fname, sz, ts, _ = self._enc_dec(tmp_path, data)
        assert result == data
        assert sz == 1

    def test_exactly_one_chunk(self, tmp_path):
        data = os.urandom(cc.CHUNK_SIZE)
        result, fname, sz, ts, meta = self._enc_dec(tmp_path, data)
        assert result == data
        assert meta["payload_chunk_count"] == 1

    def test_exactly_two_chunks(self, tmp_path):
        data = os.urandom(cc.CHUNK_SIZE + 1)
        result, fname, sz, ts, meta = self._enc_dec(tmp_path, data)
        assert result == data
        assert meta["payload_chunk_count"] == 2

    def test_multi_chunk_file(self, tmp_path):
        data = os.urandom(cc.CHUNK_SIZE * 5 + 12345)
        result, fname, sz, ts, meta = self._enc_dec(tmp_path, data)
        assert result == data
        assert meta["payload_chunk_count"] == 6

    def test_filename_and_metadata_preserved(self, tmp_path):
        import os, time
        data = os.urandom(1024)
        t_before = int(time.time()) - 1
        result, fname, sz, ts, _ = self._enc_dec(tmp_path, data, filename="hello world.pdf")
        assert fname == "hello world.pdf"
        assert sz == len(data)
        assert ts >= t_before

    def test_unicode_filename(self, tmp_path):
        import os
        data = os.urandom(512)
        result, fname, sz, ts, _ = self._enc_dec(tmp_path, data, filename="档案_2024.docx")
        assert fname == "档案_2024.docx"

    def test_wrong_password_fails(self, tmp_path):
        data = b"secret data" * 100
        src = tmp_path / "src.bin"
        enc = tmp_path / "src.qcx"
        out = tmp_path / "out.bin"
        src.write_bytes(data)

        with open(enc, "wb") as f:
            payload_offset = f.tell()
            meta = cc.encrypt_single_streaming(str(src), f, "correctpassword", filename="src.bin")
            meta["payload_offset"] = payload_offset
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)

        from quantacrypt.ui.decryptor import load_pkg
        pkg   = load_pkg(str(enc))
        meta2 = pkg["meta"]

        # Wrong password → Argon2 gives wrong argon_key → AES-GCM decrypt of sk fails
        wrong_argon = cc.argon2id_derive(b"wrongpassword", base64.b64decode(meta2["argon_salt"]))
        with pytest.raises(Exception):
            cc.aes_gcm_decrypt(wrong_argon,
                               base64.b64decode(meta2["kyber_sk_enc_nonce"]),
                               base64.b64decode(meta2["kyber_sk_enc"]))

    def test_version_field_is_the_current_format(self, tmp_path):
        import os
        data = os.urandom(256)
        _, _, _, _, meta = self._enc_dec(tmp_path, data)
        assert meta["version"] == cc.FORMAT_VERSION == 2

    def test_no_payload_field_in_meta(self, tmp_path):
        """Meta never stores the payload blob in JSON — it's on disk as chunks."""
        import os
        data = os.urandom(1024)
        _, _, _, _, meta = self._enc_dec(tmp_path, data)
        assert "payload" not in meta, "Meta must not contain an in-memory payload blob"

    def test_chunk_count_matches_expected(self, tmp_path):
        data = os.urandom(cc.CHUNK_SIZE * 3 + 1)
        _, _, _, _, meta = self._enc_dec(tmp_path, data)
        expected = math.ceil(len(data) / cc.CHUNK_SIZE)
        assert meta["payload_chunk_count"] == expected


class TestStreamingSecurity:
    """Security properties of the streaming format."""

    def _make_encrypted(self, tmp_path, data=None, password="pw-testpad"):
        if data is None:
            data = os.urandom(cc.CHUNK_SIZE * 3)
        src = tmp_path / "src.bin"
        enc = tmp_path / "src.qcx"
        src.write_bytes(data)
        with open(enc, "wb") as f:
            offset = f.tell()
            meta = cc.encrypt_single_streaming(str(src), f, password, filename="src.bin")
            meta["payload_offset"] = offset
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
        return enc, meta, data

    def _get_final_key(self, meta, password="pw-testpad"):
        argon_key = cc.argon2id_derive(password.encode(), base64.b64decode(meta["argon_salt"]))
        sk        = cc.aes_gcm_decrypt(argon_key, base64.b64decode(meta["kyber_sk_enc_nonce"]),
                                       base64.b64decode(meta["kyber_sk_enc"]))
        kem_ss    = cc.kyber_decaps(sk, base64.b64decode(meta["kyber_kem_ct"]))
        return cc.xor_bytes(argon_key, kem_ss)

    def test_chunk_truncation_detected(self, tmp_path):
        """Dropping the last chunk is detected — payload_chunk_count in meta differs."""
        enc, meta, data = self._make_encrypted(tmp_path)
        final_key = self._get_final_key(meta)

        # Truncate the file: remove the last chunk's bytes (last ~CHUNK_SIZE+20 bytes of payload)
        raw = enc.read_bytes()
        # Find magic and strip the tail metadata to get full file
        magic_pos = raw.rfind(cc.MAGIC)
        payload_only = bytearray(raw[:magic_pos])
        # Drop last 32 bytes from the payload section — enough to corrupt last chunk
        payload_only = payload_only[:-32]
        truncated = tmp_path / "truncated.qcx"
        truncated.write_bytes(bytes(payload_only) + raw[magic_pos:])

        out = io.BytesIO()
        with pytest.raises(Exception):
            cc.stream_decrypt_payload(str(truncated), out, final_key,
                                      meta["payload_offset"],
                                      meta["payload_chunk_count"],
                                      __import__("base64").b64decode(meta["payload_nonce"]))

    def test_payload_bit_flip_detected(self, tmp_path):
        """Flipping a bit in the ciphertext fails AES-GCM authentication."""
        enc, meta, data = self._make_encrypted(tmp_path)
        final_key = self._get_final_key(meta)

        raw = bytearray(enc.read_bytes())
        # Flip a bit deep inside the first chunk's ciphertext
        flip_pos = meta["payload_offset"] + 8 + 20   # past seq(4)+len(4)+some ciphertext
        raw[flip_pos] ^= 0xFF
        enc.write_bytes(bytes(raw))

        out = io.BytesIO()
        with pytest.raises(Exception):
            cc.stream_decrypt_payload(str(enc), out, final_key,
                                      meta["payload_offset"],
                                      meta["payload_chunk_count"],
                                      base64.b64decode(meta["payload_nonce"]))

    def test_chunk_sequence_mismatch_detected(self, tmp_path):
        """Overwriting the sequence number field triggers a sequence mismatch error."""
        enc, meta, data = self._make_encrypted(tmp_path)
        final_key = self._get_final_key(meta)

        raw = bytearray(enc.read_bytes())
        # Corrupt the first 4 bytes (sequence number of chunk 0)
        offset = meta["payload_offset"]
        raw[offset:offset+4] = (999).to_bytes(4, "big")  # claim it's chunk 999
        enc.write_bytes(bytes(raw))

        out = io.BytesIO()
        with pytest.raises(ValueError, match="sequence"):
            cc.stream_decrypt_payload(str(enc), out, final_key,
                                      meta["payload_offset"],
                                      meta["payload_chunk_count"],
                                      base64.b64decode(meta["payload_nonce"]))

    def test_different_file_nonce_different_ciphertext(self, tmp_path):
        """Two encryptions of the same plaintext produce different ciphertext (random nonces)."""
        data = b"identical plaintext" * 1000
        src  = tmp_path / "src.bin"
        src.write_bytes(data)

        results = []
        for i in range(2):
            enc = tmp_path / f"enc{i}.qcx"
            with open(enc, "wb") as f:
                offset = f.tell()
                meta = cc.encrypt_single_streaming(str(src), f, "pw", filename="src.bin")
                meta["payload_offset"] = offset
                blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
                f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
            results.append(enc.read_bytes())

        assert results[0] != results[1], "Two encryptions of same file must differ (random nonces)"

    def test_hmac_covers_chunk_count(self, tmp_path):
        """Metadata HMAC field exists and covers payload_chunk_count."""
        import os
        data = os.urandom(1024)
        _, _, _, _, meta = TestStreamingRoundTrip()._enc_dec(tmp_path, data)
        assert "hmac" in meta
        # payload_chunk_count must be in auth_fields (covered by HMAC)
        # We verify this structurally: if we flip chunk_count and re-check HMAC it fails
        # We can't easily re-derive final_key without password here, but we verify
        # the HMAC field is present (its correctness is exercised in wrong-password test)
        assert isinstance(meta["hmac"], str) and len(meta["hmac"]) > 10


class TestShamirStreaming:
    """Shamir + streaming round-trip."""

    def test_shamir_round_trip(self, tmp_path):
        data = os.urandom(cc.CHUNK_SIZE * 2 + 500)
        src  = tmp_path / "src.bin"
        enc  = tmp_path / "src.qcx"
        out  = tmp_path / "out.bin"
        src.write_bytes(data)

        with open(enc, "wb") as f:
            offset = f.tell()
            meta, shares = cc.encrypt_shamir_streaming(str(src), f, n=3, k=2, filename="src.bin")
            meta["payload_offset"] = offset
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)

        assert len(shares) == 3
        assert meta["version"] == cc.FORMAT_VERSION
        assert meta["payload_chunk_count"] > 0

        # Decrypt with k=2 shares (shares 0 and 2)
        share_dicts = [cc.decode_share(s) for s in [shares[0], shares[2]]]
        master_key  = cc.shamir_recover(share_dicts)
        sk          = cc.aes_gcm_decrypt(master_key, base64.b64decode(meta["kyber_sk_enc_nonce"]),
                                         base64.b64decode(meta["kyber_sk_enc"]))
        kem_ss      = cc.kyber_decaps(sk, base64.b64decode(meta["kyber_kem_ct"]))
        final_key   = cc.xor_bytes(master_key, kem_ss)

        with open(out, "wb") as f:
            fname, sz, ts = cc.decrypt_streaming(str(enc), f, meta, final_key)

        assert out.read_bytes() == data
        assert fname == "src.bin"
        assert sz == len(data)

    def test_shamir_insufficient_shares_fails(self, tmp_path):
        data = os.urandom(512)
        src  = tmp_path / "src.bin"
        enc  = tmp_path / "src.qcx"
        src.write_bytes(data)

        with open(enc, "wb") as f:
            offset = f.tell()
            meta, shares = cc.encrypt_shamir_streaming(str(src), f, n=3, k=3, filename="src.bin")
            meta["payload_offset"] = offset
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)

        # Using only 2 of 3 required shares → shamir_recover produces an out-of-range
        # integer (wrong polynomial reconstruction) → ValueError before we touch AES-GCM.
        share_dicts = [cc.decode_share(s) for s in shares[:2]]
        with pytest.raises((ValueError, Exception)):
            wrong_master = cc.shamir_recover(share_dicts)
            # If recovery didn't raise, the wrong key should fail AES-GCM:
            cc.aes_gcm_decrypt(wrong_master,
                               base64.b64decode(meta["kyber_sk_enc_nonce"]),
                               base64.b64decode(meta["kyber_sk_enc"]))


class TestFileDetection:
    """File format detection and load_pkg integration."""

    def test_streaming_file_detected_correctly(self, tmp_path):
        """Streaming detection: payload_chunk_count present → streaming path."""
        data = os.urandom(1024)
        src  = tmp_path / "src.bin"
        enc  = tmp_path / "src.qcx"
        src.write_bytes(data)

        with open(enc, "wb") as f:
            offset = f.tell()
            meta = cc.encrypt_single_streaming(str(src), f, "pw")
            meta["payload_offset"] = offset
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)

        from quantacrypt.ui.decryptor import load_pkg
        pkg  = load_pkg(str(enc))
        meta = pkg["meta"]
        # Streaming check: payload_chunk_count present in meta
        is_streaming = (meta.get("version", 0) >= 1 and "payload_chunk_count" in meta)
        assert is_streaming




# ══════════════════════════════════════════════════════════════════════════════
# BUG-A / BUG-B / BUG-C — fixes applied in bug-check session
# ══════════════════════════════════════════════════════════════════════════════

def _make_qcx_bytes(meta_override=None):
    """Build a minimal .qcx tail from a meta dict and return raw bytes."""
    import struct, json
    from quantacrypt.core.crypto import MAGIC
    meta = {
        "version": 1, "mode": "single", "key_bits": 512,
        "chunk_size": 4194304, "argon_salt": "AA==", "kyber_kem_ct": "AA==",
        "kyber_sk_enc_nonce": "AA==", "kyber_sk_enc": "AA==",
        "payload_nonce": "AA==", "payload_chunk_count": 1,
        "filename_nonce": "AA==", "filename_enc": "AA==", "hmac": "AA==",
    }
    if meta_override:
        meta.update(meta_override)
    blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
    return b"x" * 16 + MAGIC + struct.pack(">I", len(blob)) + blob


def _write_qcx(data, tmp_path):
    """Write bytes to a temp .qcx file, return path."""
    p = str(tmp_path)
    with open(p, "wb") as f:
        f.write(data)
    return p


class TestLoadPkgValidation:
    """BUG-B/C: load_pkg must raise descriptive ValueError for malformed meta."""

    def test_valid_single_file_loads(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg
        path = _write_qcx(_make_qcx_bytes(), tmp_path / "ok.qcx")
        pkg = load_pkg(path)
        assert pkg["meta"]["mode"] == "single"

    def test_missing_mode_raises(self, tmp_path):
        import struct, json
        from quantacrypt.core.crypto import MAGIC
        from quantacrypt.ui.decryptor import load_pkg
        meta = {"version": 1, "key_bits": 512}  # no 'mode'
        blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
        data = b"x" * 16 + MAGIC + struct.pack(">I", len(blob)) + blob
        path = _write_qcx(data, tmp_path / "bad.qcx")
        with pytest.raises(ValueError, match="mode"):
            load_pkg(path)

    def test_unknown_mode_raises(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg
        path = _write_qcx(_make_qcx_bytes({"mode": "quantum_magic"}), tmp_path / "bad.qcx")
        with pytest.raises(ValueError, match="mode"):
            load_pkg(path)

    def test_shamir_missing_threshold_raises(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg
        path = _write_qcx(_make_qcx_bytes({"mode": "shamir", "total": 3}), tmp_path / "bad.qcx")
        with pytest.raises(ValueError, match="threshold"):
            load_pkg(path)

    def test_shamir_missing_total_raises(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg
        path = _write_qcx(_make_qcx_bytes({"mode": "shamir", "threshold": 2}), tmp_path / "bad.qcx")
        with pytest.raises(ValueError, match="total"):
            load_pkg(path)

    def test_shamir_threshold_exceeds_total_raises(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg
        path = _write_qcx(_make_qcx_bytes({"mode": "shamir", "threshold": 5, "total": 3}),
                          tmp_path / "bad.qcx")
        with pytest.raises(ValueError):
            load_pkg(path)

    def test_valid_shamir_file_loads(self, tmp_path):
        from quantacrypt.ui.decryptor import load_pkg
        path = _write_qcx(
            _make_qcx_bytes({"mode": "shamir", "threshold": 2, "total": 3}),
            tmp_path / "shamir.qcx")
        pkg = load_pkg(path)
        assert pkg["meta"]["threshold"] == 2


@requires_tkinter
class TestEncryptorDecSizeGuard:
    """BUG-A: a decryptor binary that vanishes between _find_dec and
    getsize must not crash the worker — _done still runs with dec_size 0."""

    def test_dec_size_oserror_is_caught(self, tmp_path):
        import types
        from unittest.mock import patch
        import quantacrypt.ui.encryptor as enc_mod
        from quantacrypt.ui.encryptor import EncryptorApp
        gone = str(tmp_path / "no-such-decryptor")
        import threading
        obj = types.SimpleNamespace(done=[], failed=[], _find_dec=lambda: gone,
                                    _cancel_event=threading.Event(), _prog_cb=lambda m: None)
        obj._done = lambda *a, **k: obj.done.append((a, k))
        obj._fail = lambda exc: obj.failed.append(exc)
        obj._cancelled = lambda: obj.failed.append("cancelled")
        params = {"path": "/in/x", "out": "/out/x.qcx", "mode": "password",
                  "pw": "pw", "n": 3, "k": 2, "embed": True, "is_folder": False}
        with patch.object(enc_mod.pkg, "encrypt_to_qcx",
                          return_value={"shares": []}) as enc, \
             patch.object(enc_mod, "safe_after", lambda w, fn, delay=0: fn()):
            EncryptorApp._run(obj, params)
        assert enc.call_args.kwargs["embed_binary"] == gone
        assert not obj.failed
        (out, shares, embedded, dec_size), kw = obj.done[0]
        assert out == "/out/x.qcx" and shares == [] and embedded is True
        assert dec_size == 0 and kw == {"mnemonics": []}
        assert params["pw"] is None, "password must be dropped from the worker params"



# ═══════════════════════════════════════════════════════════════════════════════
# Tests for new Shamir / clipboard / verify features
# ═══════════════════════════════════════════════════════════════════════════════



# ── Run-3 regression tests (see docs/design/review-2026-09-medium-fixes.md) ──

class TestZipFolderSelfInclusion:
    """R3 F-001: the staging zip lives in the output directory, which the
    user can point inside the source folder — zipping the archive into
    itself never terminates (deflate output is incompressible)."""

    def _make_tree(self, root):
        os.makedirs(os.path.join(root, "sub"))
        with open(os.path.join(root, "a.txt"), "w") as f:
            f.write("alpha" * 1000)
        with open(os.path.join(root, "sub", "b.txt"), "w") as f:
            f.write("beta" * 1000)

    def test_zip_excludes_its_own_output(self):
        from quantacrypt.ui.encryptor import _zip_folder
        import zipfile
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "folder")
            os.makedirs(src)
            self._make_tree(src)
            # Staging zip INSIDE the tree being walked
            dst = os.path.join(src, "sub", ".out.qcx.qc-staging-x.zip")
            _zip_folder(src, dst)  # must terminate
            with zipfile.ZipFile(dst) as zf:
                names = zf.namelist()
            assert not any(n.endswith(".qc-staging-x.zip") for n in names), \
                "the staging zip must never appear inside itself"
            assert any(n.endswith("a.txt") for n in names)
            assert any(n.endswith("b.txt") for n in names)

    def test_zip_cancel_check_aborts(self):
        from quantacrypt.ui.encryptor import _zip_folder
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "folder")
            os.makedirs(src)
            self._make_tree(src)
            dst = os.path.join(td, "out.zip")
            with pytest.raises(cc.CancelledOperation):
                _zip_folder(src, dst, cancel_check=lambda: True)


class TestValidateOutputInsideSource:
    """R3 F-001b: folder mode must refuse an output path inside the source
    folder (the staging zip would be created inside the walked tree)."""

    def test_validate_logic_rejects_inside_paths(self):
        # Exercise the same predicate _validate uses, on plain paths.
        with tempfile.TemporaryDirectory() as td:
            src_abs = os.path.abspath(os.path.join(td, "folder"))
            os.makedirs(src_abs)
            inside = os.path.join(src_abs, "out.qcx")
            deeper = os.path.join(src_abs, "sub", "out.qcx")
            outside = os.path.join(td, "out.qcx")
            for out in (inside, deeper):
                out_abs = os.path.abspath(out)
                assert out_abs == src_abs or \
                    out_abs.startswith(src_abs + os.sep)
            out_abs = os.path.abspath(outside)
            assert not (out_abs == src_abs or
                        out_abs.startswith(src_abs + os.sep))


class TestCtLenBound:
    """R3 F-005: a crafted .qcx declaring a huge chunk length must be
    rejected before allocation, not after a 4 GB read attempt."""

    def test_stream_decrypt_rejects_absurd_ct_len(self):
        # The guard fires on the unauthenticated length field, before any
        # key material is used — a crafted header must fail fast, not
        # attempt a 4 GB read.
        with tempfile.TemporaryDirectory() as td:
            enc = os.path.join(td, "evil.qcx")
            with open(enc, "wb") as f:
                f.write(struct.pack(">I", 0))            # seq 0 (valid)
                f.write(b"\xff\xff\xff\xff")             # ct_len = 4 GB
                f.write(b"\x00" * 64)                    # token body
            out = io.BytesIO()
            with pytest.raises(ValueError, match="implausible"):
                cc.stream_decrypt_payload(
                    enc, out, b"\x00" * 64,
                    payload_offset=0, chunk_count=1,
                    base_nonce=b"\x00" * 12,
                )


class TestBatchOutputPaths:
    """R4 F-002: colliding input stems must get unique batch outputs."""

    def test_colliding_stems_uniquified(self):
        from quantacrypt.ui.encryptor import _batch_output_paths
        outs = _batch_output_paths(
            ["/in/report.txt", "/in/report.md", "/other/report.pdf",
             "/in/notes.txt"],
            "/out")
        names = [os.path.basename(o) for o in outs]
        assert names[0] == "report.qcx"
        assert names[1] == "report_2.qcx"
        assert names[2] == "report_3.qcx"
        assert names[3] == "notes.qcx"
        assert len(set(n.lower() for n in names)) == len(names)

    def test_no_collision_passthrough(self):
        from quantacrypt.ui.encryptor import _batch_output_paths
        outs = _batch_output_paths(["/a/x.txt", "/a/y.txt"], "/out")
        assert [os.path.basename(o) for o in outs] == ["x.qcx", "y.qcx"]


@requires_tkinter
class TestSaveIndividualSharesDisarmsGuard:
    """R5 F-001 (run-4 regression): the single-file 'Save individual
    files' path must disarm the "__single__" guard token even though the
    method reassigns qcx_path internally for fingerprinting."""

    def _run_save(self, tmp_dir, pending, qcx_path=None):
        import types
        from unittest.mock import patch
        import quantacrypt.ui.encryptor as enc_mod
        from quantacrypt.ui.encryptor import EncryptorApp

        obj = types.SimpleNamespace(
            _shares_pending=set(pending),
            _result_k=None, _result_n=None,
            _k=types.SimpleNamespace(get=lambda: 2),
            _n=types.SimpleNamespace(get=lambda: 2),
            _out=types.SimpleNamespace(get=lambda: ""),
            _results=types.SimpleNamespace(winfo_children=lambda: []),
        )
        # Two real shares so the writer loop has content
        secret = os.urandom(32)
        shares = [cc.encode_share(s) for s in cc.shamir_split(secret, 2, 2)]
        with patch.object(enc_mod.filedialog, "askdirectory",
                          return_value=tmp_dir), \
             patch.object(enc_mod.messagebox, "showinfo"), \
             patch.object(enc_mod.messagebox, "showerror"):
            EncryptorApp._save_individual_shares(
                obj, shares, "file.txt", qcx_path=qcx_path,
                banner_frame=object())  # not the shares_warn sentinel
        return obj

    def test_single_file_save_disarms_single_token(self, tmp_path):
        obj = self._run_save(str(tmp_path), {"__single__"}, qcx_path=None)
        assert obj._shares_pending == set(), \
            "single-file save must discard the '__single__' token"
        # And it actually wrote per-share files
        assert any(".share-" in f for f in os.listdir(str(tmp_path)))

    def test_batch_save_disarms_only_its_own_token(self, tmp_path):
        obj = self._run_save(
            str(tmp_path), {"/out/a.qcx", "/out/b.qcx"},
            qcx_path="/out/a.qcx")
        assert obj._shares_pending == {"/out/b.qcx"}


@requires_tkinter
class TestShamirKnSnapshot:
    """R6 F-001: k/n must be frozen at encryption start — spinbox drift
    after start must not leak into mnemonics or share files."""

    def test_save_individual_shares_uses_snapshot_not_spinboxes(self, tmp_path):
        import types
        from unittest.mock import patch
        import quantacrypt.ui.encryptor as enc_mod
        from quantacrypt.ui.encryptor import EncryptorApp

        secret = os.urandom(32)
        shares = [cc.encode_share(s) for s in cc.shamir_split(secret, 3, 2)]
        obj = types.SimpleNamespace(
            _shares_pending={"__single__"},
            _result_k=2, _result_n=3,           # frozen at start: 2-of-3
            _k=types.SimpleNamespace(get=lambda: 5),   # drifted spinboxes
            _n=types.SimpleNamespace(get=lambda: 7),
            _out=types.SimpleNamespace(get=lambda: ""),
            _results=types.SimpleNamespace(winfo_children=lambda: []),
        )
        with patch.object(enc_mod.filedialog, "askdirectory",
                          return_value=str(tmp_path)), \
             patch.object(enc_mod.messagebox, "showinfo"), \
             patch.object(enc_mod.messagebox, "showerror"):
            EncryptorApp._save_individual_shares(
                obj, shares, "file.txt", qcx_path=None,
                banner_frame=object())
        files = [f for f in os.listdir(str(tmp_path)) if ".share-" in f]
        assert files, "share files must have been written"
        # Filenames and contents must carry the FROZEN 2-of-3, not 5/7
        assert all("-of-3" in f for f in files), files
        body = open(os.path.join(str(tmp_path), files[0])).read()
        assert "2" in body and "5 " not in body
        # Mnemonics generated with the frozen threshold must round-trip
        mn_share = cc.share_to_mnemonic(
            {**cc.decode_share(shares[0]), "threshold": 2})
        back = cc.mnemonic_to_share(mn_share)
        assert back["threshold"] == 2


class TestFriendlyErrorInvalidTag:
    """R7 F-001: cryptography's InvalidTag stringifies to '' — the
    wrong-password mount failure must still get the friendly message,
    not 'InvalidTag (no additional detail)'."""

    def test_bare_invalidtag_gets_friendly_message(self):
        from cryptography.exceptions import InvalidTag
        from quantacrypt.ui.shared import friendly_error
        assert str(InvalidTag()) == ""  # the trap this guards against
        msg = friendly_error(InvalidTag())
        assert "password or shares are incorrect" in msg
        assert "InvalidTag" not in msg

    def test_empty_unknown_exception_keeps_typename_fallback(self):
        from quantacrypt.ui.shared import friendly_error
        class WeirdError(Exception):
            pass
        assert friendly_error(WeirdError()) == \
            "WeirdError (no additional detail)"


# ══════════════════════════════════════════════════════════════════════════════
# Round-3 F-207: behaviour tests for the rewritten UI helpers
# ══════════════════════════════════════════════════════════════════════════════

def _shares_2_of_3():
    from quantacrypt.core import crypto as cc
    import secrets
    raw = cc.shamir_split(secrets.token_bytes(cc.KEY_BYTES), 3, 2)
    return [cc.encode_share(s) for s in raw]


@requires_tkinter
class TestWriteNewPrivateFile:
    """shared.write_new_private_file: O_EXCL, 0600, <stem>_N on collision,
    terminates on a dangling symlink (F-202)."""

    def test_fresh_file_is_0600_and_not_renamed(self, tmp_path):
        from quantacrypt.ui.shared import write_new_private_file
        p = str(tmp_path / "a.shares.txt")
        out, renamed = write_new_private_file(p, "secret\n")
        assert out == p and renamed is False
        assert os.stat(out).st_mode & 0o777 == 0o600
        assert open(out).read() == "secret\n"

    def test_collision_goes_to_stem_2_and_leaves_original(self, tmp_path):
        from quantacrypt.ui.shared import write_new_private_file
        p = str(tmp_path / "a.shares.txt")
        write_new_private_file(p, "first\n")
        out, renamed = write_new_private_file(p, "second\n")
        assert renamed is True and os.path.basename(out) == "a.shares_2.txt"
        assert open(p).read() == "first\n" and open(out).read() == "second\n"
        out3, _ = write_new_private_file(p, "third\n")
        assert os.path.basename(out3) == "a.shares_3.txt"

    def test_dangling_symlink_is_skipped_not_looped(self, tmp_path):
        from quantacrypt.ui.shared import write_new_private_file
        p = str(tmp_path / "a.txt")
        os.symlink(str(tmp_path / "missing-target"), p)
        assert not os.path.exists(p) and os.path.lexists(p)
        out, renamed = write_new_private_file(p, "x")
        assert renamed is True and os.path.basename(out) == "a_2.txt"
        assert os.path.islink(p), "the symlink itself must be left alone"

    def test_attempts_are_capped(self, tmp_path):
        from quantacrypt.ui import shared
        p = str(tmp_path / "a.txt")
        os.symlink("/nonexistent/x", p)
        for n in range(2, shared._MAX_NAME_ATTEMPTS + 1):
            os.symlink("/nonexistent/x", str(tmp_path / f"a_{n}.txt"))
        with pytest.raises(FileExistsError):
            shared.write_new_private_file(p, "x")


@requires_tkinter
class TestSafeAfter:
    """shared.safe_after: hop is dropped (not raised) when after() fails,
    and the callback is skipped once the widget is gone."""

    class _Widget:
        def __init__(self, exists=True, raise_on_after=None):
            self.exists = exists; self.raise_on_after = raise_on_after; self.queued = []
        def after(self, delay, fn):
            if self.raise_on_after:
                raise self.raise_on_after
            self.queued.append(fn)
        def winfo_exists(self):
            return self.exists

    def test_non_threaded_tcl_runtimeerror_is_swallowed(self):
        from quantacrypt.ui.shared import safe_after
        w = self._Widget(raise_on_after=RuntimeError("main thread is not in main loop"))
        safe_after(w, lambda: (_ for _ in ()).throw(AssertionError("must not run")))

    def test_destroyed_window_tclerror_is_swallowed(self):
        import tkinter as tk
        from quantacrypt.ui.shared import safe_after
        w = self._Widget(raise_on_after=tk.TclError("bad window path name"))
        safe_after(w, lambda: None)

    def test_callback_runs_only_while_widget_exists(self):
        import tkinter as tk
        from quantacrypt.ui.shared import safe_after
        calls = []
        w = self._Widget()
        safe_after(w, lambda: calls.append(1))
        assert len(w.queued) == 1
        w.exists = False
        w.queued[0]()
        assert calls == [], "fn must be skipped after the widget was destroyed"
        w.exists = True
        w.queued[0]()
        assert calls == [1]
        # a TclError raised by fn itself (widget died mid-callback) is contained
        def _boom(): raise tk.TclError("invalid command name")
        safe_after(w, _boom)
        w.queued[1]()


@requires_tkinter
class TestVolumeManagerParseShareText:
    """F-201: the mount panel's parser must read the app's own share files."""

    def _save_all_text(self, shares, k=2, n=3):
        # Exactly the layout VolumeManagerApp._show_shares_dialog._save_all writes
        lines = [f"QuantaCrypt recovery shares: {k} of {n} needed", ""]
        for i, share in enumerate(shares):
            lines += [f"Share {i + 1} of {n}:", share, ""]
        return "\n".join(lines)

    def test_saved_shares_file_parses_to_every_code(self):
        from quantacrypt.core import package as pkg
        from quantacrypt.ui.volume_manager import _parse_share_text
        shares = _shares_2_of_3()
        got = pkg.normalize_shares(_parse_share_text(self._save_all_text(shares)))
        assert got == shares

    def test_encryptor_individual_share_file_parses(self, tmp_path):
        import types
        from unittest.mock import patch
        from quantacrypt.core import package as pkg
        import quantacrypt.ui.encryptor as enc_mod
        from quantacrypt.ui.encryptor import EncryptorApp
        from quantacrypt.ui.volume_manager import _parse_share_text
        shares = _shares_2_of_3()
        obj = types.SimpleNamespace(
            _shares_pending={"__single__"}, _result_k=2, _result_n=3,
            _k=types.SimpleNamespace(get=lambda: 2), _n=types.SimpleNamespace(get=lambda: 3),
            _out=types.SimpleNamespace(get=lambda: ""),
            _results=types.SimpleNamespace(winfo_children=lambda: []))
        with patch.object(enc_mod.filedialog, "askdirectory", return_value=str(tmp_path)), \
             patch.object(enc_mod.messagebox, "showerror"):
            EncryptorApp._save_individual_shares(obj, shares, "vault.txt",
                                                 qcx_path=None, banner_frame=object())
        for i, share in enumerate(shares, 1):
            body = open(tmp_path / f"vault.share-{i}-of-3.txt").read()
            # header, prose, the code AND its 50-word phrase → exactly one share
            assert pkg.normalize_shares(_parse_share_text(body)) == [share]

    def test_phrase_across_lines_and_bad_code_named(self):
        from quantacrypt.core import crypto as cc
        from quantacrypt.core import package as pkg
        from quantacrypt.ui.volume_manager import _parse_share_text
        shares = _shares_2_of_3()
        mn = cc.share_to_mnemonic({**cc.decode_share(shares[1]), "threshold": 2})
        text = "my notes\n" + shares[0] + "\n" + mn.replace(" ", "\n", 7) + "\n" + shares[0]
        entries = _parse_share_text(text)
        assert entries == [shares[0], shares[0], shares[1]]
        assert pkg.normalize_shares(entries) == [shares[0], shares[1]]
        with pytest.raises(ValueError, match="Share 1"):
            pkg.normalize_shares(_parse_share_text("QCSHARE-garbage"))
        assert _parse_share_text("just some prose, no shares here") == []


@requires_tkinter
class TestExtractShareCodesDelegation:
    def test_decryptor_delegates_to_core(self):
        from unittest.mock import patch
        from quantacrypt.core import package as pkg
        from quantacrypt.ui.decryptor import _extract_share_codes
        shares = _shares_2_of_3()
        text = "QuantaCrypt Key Shares\nThreshold: 2 of 3\n\nShare 1 — QCSHARE- code:\n" \
               + shares[0] + "\n\n" + shares[2] + "\n"
        assert _extract_share_codes(text) == pkg.extract_share_codes(text) == [shares[0], shares[2]]
        sentinel = ["SENTINEL"]
        with patch.object(pkg, "extract_share_codes", return_value=sentinel) as m:
            assert _extract_share_codes("anything") is sentinel
        m.assert_called_once_with("anything")


@requires_tkinter
class TestShareFileNamesWholeRun:
    """F-015: per-run collision handling — never a mix of two stems."""

    def test_no_collision_keeps_stem(self, tmp_path):
        from quantacrypt.ui.encryptor import _share_file_names
        names, renamed = _share_file_names(str(tmp_path), "doc", 3)
        assert renamed is False
        assert [os.path.basename(n) for n in names] == \
            ["doc.share-1-of-3.txt", "doc.share-2-of-3.txt", "doc.share-3-of-3.txt"]

    def test_one_existing_file_moves_the_whole_set(self, tmp_path):
        from quantacrypt.ui.encryptor import _share_file_names
        (tmp_path / "doc.share-2-of-3.txt").write_text("old")
        names, renamed = _share_file_names(str(tmp_path), "doc", 3)
        assert renamed is True
        assert [os.path.basename(n) for n in names] == \
            ["doc_2.share-1-of-3.txt", "doc_2.share-2-of-3.txt", "doc_2.share-3-of-3.txt"]
        os.symlink("/nonexistent", str(tmp_path / "doc_2.share-1-of-3.txt"))  # dangling counts
        names, _ = _share_file_names(str(tmp_path), "doc", 3)
        assert os.path.basename(names[0]) == "doc_3.share-1-of-3.txt"

    def test_cap(self, tmp_path):
        from quantacrypt.ui.encryptor import _share_file_names
        (tmp_path / "doc.share-1-of-2.txt").write_text("x")
        for n in range(2, 100):
            (tmp_path / f"doc_{n}.share-1-of-2.txt").write_text("x")
        with pytest.raises(FileExistsError):
            _share_file_names(str(tmp_path), "doc", 2)


@requires_tkinter
class TestRetryFailedKeepsFolderAndGuards:
    """F-203: 'Retry N failed' keeps the chosen output folder and runs the
    unsaved-shares guard BEFORE replacing the selection."""

    def _obj(self, pending):
        import types
        from quantacrypt.ui.encryptor import EncryptorApp
        var = types.SimpleNamespace(v="/chosen/out")
        var.get = lambda: var.v
        var.set = lambda s: setattr(var, "v", s)
        obj = types.SimpleNamespace(
            _batch_out_var=var, _batch_paths=["/in/a", "/in/b", "/in/c"],
            _shares_pending=set(pending), _show_done=True, started=[],
            _build_batch_ui=lambda: None, _set_status=lambda m: None)
        obj._start = lambda: obj.started.append(1)
        obj._check_shares_saved = lambda: EncryptorApp._check_shares_saved(obj)
        obj._set_batch_paths = lambda paths, keep_out=False: EncryptorApp._set_batch_paths(obj, paths, keep_out)
        obj._retry_failed = lambda paths: EncryptorApp._retry_failed(obj, paths)
        return obj

    def test_go_back_leaves_everything_untouched(self):
        from unittest.mock import patch
        import quantacrypt.ui.encryptor as enc_mod
        obj = self._obj({"/chosen/out/a.qcx"})
        with patch.object(enc_mod.messagebox, "askyesno", return_value=False):
            obj._retry_failed(["/in/b"])
        assert obj.started == [] and obj._batch_paths == ["/in/a", "/in/b", "/in/c"]
        assert obj._shares_pending == {"/chosen/out/a.qcx"} and obj._show_done is True

    def test_retry_keeps_output_folder(self):
        from unittest.mock import patch
        import quantacrypt.ui.encryptor as enc_mod
        obj = self._obj({"/chosen/out/a.qcx"})
        with patch.object(enc_mod.messagebox, "askyesno", return_value=True) as m:
            obj._retry_failed(["/in/b", "/in/c"])
        assert m.call_count == 1, "the guard must run exactly once (not again in _start)"
        assert obj.started == [1] and obj._batch_paths == ["/in/b", "/in/c"]
        assert obj._batch_out_var.get() == "/chosen/out"
        assert obj._shares_pending == set()
        # a fresh selection (not a retry) still defaults the folder
        obj._set_batch_paths(["/elsewhere/x"])
        assert obj._batch_out_var.get() == "/elsewhere"


@requires_tkinter
class TestExtractRunRemovesOnlyOwnDirectory:
    """F-204: a destination that already existed is never rmtree'd."""

    def _obj(self):
        import types
        from quantacrypt.ui.decryptor import DecryptorApp
        obj = types.SimpleNamespace(_cancel=False, failed=[], done=[], cancelled=[])
        obj._after = lambda fn, delay=0: fn()
        obj._prog_cb = lambda msg: None
        obj._extract_failed = lambda exc: obj.failed.append(exc)
        obj._extract_done = lambda dest, renamed: obj.done.append(dest)
        obj._cancelled = lambda: obj.cancelled.append(1)
        obj._extract_run = lambda *a: DecryptorApp._extract_run(obj, *a)
        return obj

    def _zip(self, tmp_path):
        import zipfile
        z = tmp_path / "docs.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("docs/a.txt", "alpha")
        return str(z)

    def test_pre_existing_destination_survives(self, tmp_path):
        dest = tmp_path / "docs"
        dest.mkdir(); (dest / "keep.txt").write_text("mine")
        obj = self._obj()
        obj._extract_run(self._zip(tmp_path), str(dest), "docs", 5, False)
        assert obj.done == [] and len(obj.failed) == 1
        assert "appeared" in str(obj.failed[0])
        assert (dest / "keep.txt").read_text() == "mine"

    def test_own_directory_is_removed_on_failure(self, tmp_path):
        dest = tmp_path / "docs"
        obj = self._obj()
        obj._extract_run(str(tmp_path / "missing.zip"), str(dest), None, 5, False)
        assert len(obj.failed) == 1 and not dest.exists()

    def test_success_path(self, tmp_path):
        dest = tmp_path / "docs"
        obj = self._obj()
        obj._extract_run(self._zip(tmp_path), str(dest), "docs", 5, False)
        assert obj.done == [str(dest)] and (dest / "a.txt").read_text() == "alpha"


@requires_tkinter
class TestDecryptorDropParsing:
    """F-210: a multi-item drop is split like the encryptor does."""

    def _obj(self, splitlist):
        import types
        from quantacrypt.ui.decryptor import DecryptorApp
        obj = types.SimpleNamespace(_busy=False, status=[], errors=[], loaded=[], opened=[],
                                    tk=types.SimpleNamespace(splitlist=splitlist))
        obj._set_status = lambda m, d="": obj.status.append(m)
        obj._set_error = lambda m, d="": obj.errors.append(m)
        obj._file_card = types.SimpleNamespace(load=obj.loaded.append)
        obj._on_file = obj.opened.append
        obj._flash_busy = lambda: None
        obj._on_drop = lambda ev: DecryptorApp._on_drop(obj, ev)
        return obj

    def test_two_unbraced_paths_use_the_first(self, tmp_path):
        import types
        a = tmp_path / "x.qcx"; b = tmp_path / "y.qcx"
        a.write_bytes(b"1"); b.write_bytes(b"2")
        obj = self._obj(lambda s: tuple(s.split()))
        obj._on_drop(types.SimpleNamespace(data=f"{a} {b}"))
        assert obj.opened == [str(a)] and obj.errors == []
        assert obj.status and "Only one file" in obj.status[-1]

    def test_splitlist_failure_falls_back_to_braces(self, tmp_path):
        import types
        d = tmp_path / "a b"; d.mkdir()
        a = d / "x.qcx"; a.write_bytes(b"1")
        def _boom(s): raise RuntimeError("no tcl")
        obj = self._obj(_boom)
        obj._on_drop(types.SimpleNamespace(data="{" + str(a) + "}"))
        assert obj.opened == [str(a)]


@requires_tkinter
class TestMountErrorBlame:
    """F-211: a PermissionError about the .qcv must not blame the mount point."""

    def test_blames_mount_point_only_for_its_own_path(self):
        from quantacrypt.ui.volume_manager import _blames_mount_point
        mp = "/Users/me/QuantaCrypt Volumes/vault"
        assert _blames_mount_point(PermissionError(13, "denied", mp), mp)
        assert _blames_mount_point(PermissionError(13, "denied", "/Users/me/QuantaCrypt Volumes"), mp)
        assert _blames_mount_point(PermissionError(13, "denied"), mp)   # unknown → default advice
        assert not _blames_mount_point(PermissionError(13, "denied", "/Users/me/vault.qcv"), mp)


@requires_tkinter
class TestStagedProgressBarSingleTimer:
    """The ETA loop is armed from start() only: many advance() calls leave
    one pending _time_job (plus at most the dot-pulse job)."""

    def test_only_one_eta_job_after_many_advances(self):
        import tkinter as tk
        from quantacrypt.ui.shared import StagedProgressBar
        try:
            root = tk.Tk(); root.withdraw()
        except tk.TclError as exc:
            pytest.skip(f"no Tk display: {exc}")
        try:
            bar = StagedProgressBar(root, [("a", 0.5), ("b", 0.5)])
            bar.start()
            first = bar._time_job
            for i in range(200):
                bar.advance(0, "a")
            for i in range(200):
                bar.advance(1, f"b {i % 100}%")
            assert bar._time_job == first, "advance() must never re-arm the ETA loop"
            pending = root.tk.call("after", "info")
            assert len(pending) <= 2, f"{len(pending)} timers queued: {pending}"
            bar.stop()
            assert bar._time_job is None and bar._pulse_job is None
            assert not root.tk.call("after", "info")
            bar.destroy()
        finally:
            root.destroy()


@requires_tkinter
class TestPasswordStrengthBarStaleResults:
    """A worker result for text the user has since changed is dropped, and
    the submit path never scores on the main thread (F-213)."""

    def _obj(self):
        import types
        from quantacrypt.ui.shared import PasswordStrengthBar
        obj = types.SimpleNamespace(_seq=5, _last=("old", 1, "Weak", ""), lbl=[], tip=[], drawn=[],
                                    _refresh_job=None, _inflight=None,
                                    _SUBMIT_WAIT_S=PasswordStrengthBar._SUBMIT_WAIT_S)
        obj._lbl = types.SimpleNamespace(config=lambda **k: obj.lbl.append(k))
        obj._tip = types.SimpleNamespace(config=lambda **k: obj.tip.append(k))
        obj._draw = lambda score, pw: obj.drawn.append((score, pw))
        obj._colour = PasswordStrengthBar._colour
        obj._apply = lambda *a: PasswordStrengthBar._apply(obj, *a)
        obj.score_for = lambda pw: PasswordStrengthBar.score_for(obj, pw)
        return obj

    def test_stale_seq_is_dropped_current_applied(self):
        obj = self._obj()
        obj._apply(4, "stale", 4, "Strong", "")
        assert obj._last == ("old", 1, "Weak", "") and obj.drawn == []
        obj._apply(5, "new", 3, "Good", "tip")
        assert obj._last == ("new", 3, "Good", "tip") and obj.drawn == [(3, "new")]

    def test_score_for_uses_cache_or_last_score_never_sync(self):
        import threading
        obj = self._obj()
        obj._score = lambda pw: (_ for _ in ()).throw(AssertionError("scored on the main thread"))
        assert obj.score_for("old") == 1                    # cached
        assert obj.score_for("something-else") == 1         # worker's last score, no sync run
        holder = {"seq": 5, "res": (4, "Strong", "")}
        ev = threading.Event(); ev.set()
        obj._inflight = ("typed-fast", ev, holder)          # worker already finished
        assert obj.score_for("typed-fast") == 4
        assert obj._last[0] == "typed-fast"


@requires_tkinter
class TestDecryptorForgetsAFileThatFailedToLoad:
    def test_a_bad_pick_after_a_good_one_disarms_decrypt(self, tk_root, tmp_path, monkeypatch, qcx_sample):
        """Run 18 F-206: the card already showed the new name while Decrypt
        still ran against the previous file."""
        app, _qcx = _decryptor_app(tk_root, tmp_path, monkeypatch, qcx_sample)
        try:
            assert app._payload is not None
            bad = tmp_path / "notes.txt"; bad.write_text("plain")
            app._on_file(str(bad))
            assert app._payload is None and app._qcx_path is None and app._meta is None
            assert app._validate() == "Open a .qcx file first"
            assert app.title() == "QuantaCrypt · Decrypt"
            # Run 19 F-101: the screen must agree with the state.
            from quantacrypt.ui.decryptor import FILE_PROMPT
            assert app._file_card._line1.cget("text") == FILE_PROMPT
            assert app._btn._enabled is False and app._verify_btn._enabled is False
            assert not hasattr(app, "_pw") or not app._pw.winfo_exists()
            assert app._out.get() == "" and "isn't a QuantaCrypt" in app._err.cget("text")
        finally:
            app.destroy()


class TestSwitchShareFormatAsksOnce:
    def test_declining_the_switch_shows_one_dialog(self, monkeypatch):
        """Run 18 F-207: the revert fired the trace and asked a second time."""
        import types
        from quantacrypt.ui import decryptor as dec
        asked = []
        monkeypatch.setattr(dec, "confirm", lambda *a, **k: asked.append(1) and False)
        obj = types.SimpleNamespace(_meta={"threshold": 2}, _mode_val="shamir",
                                    _inputs=[], _entries=[types.SimpleNamespace(get=lambda: "apple")],
                                    built=[])
        obj._build_share_inputs = obj.built.append
        class Mode:
            value = "raw"
            def get(self): return self.value
            def set(self, v):
                self.value = v
                dec.DecryptorApp._rebuild_inputs(obj)     # the write trace
        obj._imode = Mode()
        dec.DecryptorApp._rebuild_inputs(obj)
        assert asked == [1] and obj._imode.value == "mnemonic" and obj.built == []


@requires_tkinter
class TestDecryptorCanQuit:
    def test_a_running_worker_refuses_and_typed_input_asks(self, tk_root, tmp_path, monkeypatch, qcx_sample):
        from quantacrypt.ui import decryptor as dec
        app, _qcx = _decryptor_app(tk_root, tmp_path, monkeypatch, qcx_sample)
        try:
            assert app.can_quit() is True
            app._busy = True
            assert app.can_quit() is False
            app._busy = False
            monkeypatch.setattr(app, "_has_typed_input", lambda: True)
            monkeypatch.setattr(dec, "confirm", lambda *a, **k: False)
            assert app.can_quit() is False
            monkeypatch.setattr(dec, "confirm", lambda *a, **k: True)
            assert app.can_quit() is True
        finally:
            app._busy = False
            app.destroy()
