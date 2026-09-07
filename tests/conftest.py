"""Shared pytest fixtures for QuantaCrypt test suite."""

import base64
import io
import json
import functools
import os
import pathlib
import struct
import sys
import tempfile

import pytest

# Stub tkinter on headless systems so tests that import UI modules don't fail.
# This must run before any test module triggers `import tkinter`.
#
# Probed with find_spec rather than a real import: importing tkinter loads
# Tcl into EVERY pytest process, including the xdist workers that run no GUI
# test at all. libfuse's fuse_kern_mount() calls fork(), and Tcl's atfork
# handler then crashes in a process that has Tcl loaded but no live
# interpreter — observed as "Fatal Python error: Illegal instruction" with
# fuse_kern_mount -> fork -> Tcl_InitNotifier on the C stack, during
# test_mount_without_fusepy_raises. Nothing here needs the module itself,
# only whether it exists.
import importlib.util

HAS_TKINTER = importlib.util.find_spec("tkinter") is not None
if not HAS_TKINTER:
    from unittest.mock import MagicMock
    for _mod in ("tkinter", "tkinter.ttk", "tkinter.filedialog",
                 "tkinter.messagebox", "tkinterdnd2"):
        sys.modules.setdefault(_mod, MagicMock())

requires_tkinter = pytest.mark.skipif(
    not HAS_TKINTER,
    reason="Needs real tkinter (UI classes are MagicMock on headless systems)",
)


def fusepy_backend():
    """Return the ``fuse`` module, or skip the calling test.

    Not ``pytest.importorskip``: fusepy raises OSError (not ImportError)
    when the package is installed but no libfuse backend loads, which is
    the state of every macOS CI runner — the v1.4.0 release run failed
    eight tests this way. CI's Ubuntu job installs libfuse2 and asserts
    that these tests really ran, so the skip cannot hide a regression.
    """
    try:
        import fuse
    except (ImportError, OSError) as exc:
        pytest.skip(f"fusepy/libfuse unavailable: {exc}")
    return fuse

from quantacrypt.core import crypto as cc

MAGIC = cc.MAGIC


def make_pkg_bytes(meta, original_name="test.bin"):
    """Create a QuantaCrypt package bytestring from metadata."""
    pkg = {"meta": meta, "original_name": original_name}
    blob = json.dumps(pkg, separators=(",", ":")).encode()
    return MAGIC + len(blob).to_bytes(4, "big") + blob


def load_pkg(data):
    """Load package metadata from QuantaCrypt bytestring."""
    i = data.rfind(MAGIC)
    if i < 0:
        raise ValueError("Not a QuantaCrypt file")
    o = i + len(MAGIC)
    n = struct.unpack(">I", data[o : o + 4])[0]
    return json.loads(data[o + 4 : o + 4 + n])


def _make_qcx(tmp_path, data, password="pw-testpad", filename="test.bin", n=None, k=None):
    """Write a .qcx and return (path, meta, shares, final_key)."""
    src = tmp_path / "src.bin"; src.write_bytes(data)
    enc = tmp_path / "enc.qcx"
    with open(enc, "wb") as f:
        off = f.tell()
        if n is not None:
            meta, shares = cc.encrypt_shamir_streaming(str(src), f, n=n, k=k, filename=filename)
        else:
            meta = cc.encrypt_single_streaming(str(src), f, password, filename=filename)
            shares = []
        meta["payload_offset"] = off
        blob = json.dumps({"meta": meta}, separators=(",",":")).encode()
        f.write(cc.MAGIC + len(blob).to_bytes(4,"big") + blob)
    # Derive final_key
    if n is not None:
        sd  = [cc.decode_share(s) for s in shares[:k]]
        mk  = cc.shamir_recover(sd)
        sk  = cc.aes_gcm_decrypt(mk, base64.b64decode(meta["kyber_sk_enc_nonce"]),
                                  base64.b64decode(meta["kyber_sk_enc"]))
        ks  = cc.kyber_decaps(sk, base64.b64decode(meta["kyber_kem_ct"]),
                              cc.validate_kem(meta.get("kem")))
        fk  = cc.xor_bytes(mk, ks)
    else:
        ak  = cc.argon2id_derive(password.encode(), base64.b64decode(meta["argon_salt"]),
                                 meta.get("argon2"))
        sk  = cc.aes_gcm_decrypt(ak, base64.b64decode(meta["kyber_sk_enc_nonce"]),
                                  base64.b64decode(meta["kyber_sk_enc"]))
        ks  = cc.kyber_decaps(sk, base64.b64decode(meta["kyber_kem_ct"]),
                              cc.validate_kem(meta.get("kem")))
        fk  = cc.xor_bytes(ak, ks)
    return enc, meta, shares, fk


def _decrypt_qcx(enc_path, meta, final_key):
    """Decrypt a .qcx and return (data, fname, sz, ts)."""
    buf = io.BytesIO()
    fname, sz, ts = cc.decrypt_streaming(str(enc_path), buf, meta, final_key)
    return buf.getvalue(), fname, sz, ts


def pytest_terminal_summary(terminalreporter, config):
    """Print a clickable file:// link to the HTML coverage report."""
    cov_dir = os.path.join(config.rootdir, "htmlcov", "index.html")
    if os.path.isfile(cov_dir):
        url = f"file://{os.path.abspath(cov_dir)}"
        terminalreporter.write_sep("=", "coverage report")
        terminalreporter.write_line(f"  HTML: {url}")


@pytest.fixture
def tmp_dir():
    """Provide a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def sample_file(tmp_dir):
    """Create a small sample file for encryption tests."""
    path = os.path.join(tmp_dir, "sample.bin")
    with open(path, "wb") as f:
        f.write(os.urandom(256))
    return path


# ── Argon2id cost during tests ────────────────────────────────────────────
# The shipped parameters (t=4, m=64 MiB) are deliberately expensive — that is
# the point of a password KDF — and they put a hard ~0.6 s floor under every
# test that creates a .qcv or .qcx. Measured: 0.614 s per volume at the real
# parameters, 0.049 s at t=1/m=8 MiB. With well over a thousand such tests
# that difference is the single largest cost in the suite.
#
# Since format 2 (.qcx) / 3 (.qcv) a container RECORDS its Argon2 parameters
# and validate_argon2_params accepts these test-grade values on read, so a
# container written under pytest opens in production — silently weak.  That
# is the trap: a fixture-generation script run under pytest would commit a
# weak file.  TestShippedArgon2Parameters pins the shipped constants and
# TestFixtureKdfFloor (test_review_run13.py) reads every committed fixture's
# recorded parameters, so the trap cannot close unnoticed.  (Format-1
# containers, which record nothing, are only openable by code using the same
# constants — the reason this comment used to give.)
# It is also the only knob that does not change what is being tested: no test
# asserts a derived key against a fixed vector.
#
# The shipped values are pinned separately by TestShippedArgon2Parameters,
# which carries the `real_argon2` marker and therefore opts out of this.

_TEST_ARGON2_TIME_COST = 1
_TEST_ARGON2_MEMORY_COST = 8192


def _argon2_targets():
    """Every module holding its own binding of the two constants."""
    mods = []
    try:
        from quantacrypt.core import crypto as _cc
        mods.append(_cc)
    except Exception:
        pass
    return mods


#: The shipped values, captured before anything is patched.
_REAL_ARGON2: dict = {}


def pytest_configure(config):
    """Apply the cheap parameters for the whole session, not per test.

    A function-scoped fixture is too late: pytest builds higher-scoped
    fixtures FIRST, so a session- or module-scoped fixture that encrypts
    something did so at the real cost and the test body then tried to open it
    at the cheap one. Format-1 containers record no KDF parameters, so that
    mismatch surfaced as InvalidTag — nine tests failed exactly this way.
    """
    for mod in _argon2_targets():
        _REAL_ARGON2.setdefault(
            "time", getattr(mod, "ARGON2_TIME_COST", None))
        _REAL_ARGON2.setdefault(
            "memory", getattr(mod, "ARGON2_MEMORY_COST", None))
        if hasattr(mod, "ARGON2_TIME_COST"):
            mod.ARGON2_TIME_COST = _TEST_ARGON2_TIME_COST
        if hasattr(mod, "ARGON2_MEMORY_COST"):
            mod.ARGON2_MEMORY_COST = _TEST_ARGON2_MEMORY_COST


@pytest.fixture(autouse=True)
def _cheap_argon2(request, monkeypatch):
    """Restore the shipped parameters for tests marked `real_argon2`."""
    if not request.node.get_closest_marker("real_argon2"):
        return
    for mod in _argon2_targets():
        if _REAL_ARGON2.get("time") is not None and hasattr(mod, "ARGON2_TIME_COST"):
            monkeypatch.setattr(mod, "ARGON2_TIME_COST", _REAL_ARGON2["time"])
        if _REAL_ARGON2.get("memory") is not None and hasattr(mod, "ARGON2_MEMORY_COST"):
            monkeypatch.setattr(mod, "ARGON2_MEMORY_COST", _REAL_ARGON2["memory"])


# ── Keep test windows off the user's screen ───────────────────────────────
# The GUI suite drives ~1,500 real Tk widgets, and the windows were landing
# top-left of the display and flashing through the whole run.
#
# Parking them off-screen does not work: macOS clamps a window's geometry to
# the visible display, so "480x360-4000-4000" is silently pulled back to
# (0, 30) — measured. withdraw() does hide them, but Tk drops event_generate
# key events on a non-viewable window, and these tests press real keys.
#
# Zero alpha is the one option that satisfies both: the window stays mapped
# and event-capable, and the compositor never draws it. Verified against
# CGWindowList — alpha 1.0 and on-screen before, absent after.
#
# Set QC_SHOW_TEST_WINDOWS=1 to watch the tests drive the UI.

#: Toggled per test by `_window_visibility`. A transparent window does not
#: take focus on macOS, so the handful of tests that drive a real completion
#: dropdown or focus-follows behaviour have to opt out.
_HIDING_SUSPENDED = False


@pytest.fixture(autouse=True)
def _window_visibility(request):
    """Let a test opt out of window hiding with @pytest.mark.needs_real_window.

    Measured: hiding Toplevels broke exactly one test — the WordEntry
    completion dropdown never opened, because an alpha-0 window does not take
    focus. Rather than stop hiding Toplevels (which is what actually keeps
    the screen clear, since the app's own windows are Toplevels), the one
    test that needs a real window says so.
    """
    global _HIDING_SUSPENDED
    if request.node.get_closest_marker("needs_real_window"):
        _HIDING_SUSPENDED = True
        try:
            yield
        finally:
            _HIDING_SUSPENDED = False
    else:
        yield


@pytest.fixture(scope="session", autouse=True)
def _hide_tk_windows():
    """Make every Tk window created during the session invisible.

    Patched at the class level rather than in each fixture because most of
    the windows are created inside production code — confirm() dialogs, the
    shares dialog, completion dropdowns — which the tests never construct
    directly.
    """
    if os.environ.get("QC_SHOW_TEST_WINDOWS") or not _SESSION_HAS_GUI:
        # Importing tkinter here would load Tcl into every worker, including
        # the ones running the FUSE tests, whose fork() then dies in Tcl's
        # atfork handler.
        yield
        return
    try:
        import tkinter as tk
    except Exception:
        yield
        return

    def _invisible(cls, original):
        def __init__(self, *a, **kw):
            original(self, *a, **kw)
            if _HIDING_SUSPENDED:
                return
            try:
                self.attributes("-alpha", 0.0)
            except Exception:
                pass          # not every platform/window kind supports it
        return __init__

    originals = {}
    for cls in (tk.Tk, tk.Toplevel):
        originals[cls] = cls.__init__
        cls.__init__ = _invisible(cls, originals[cls])
    try:
        yield
    finally:
        for cls, original in originals.items():
            cls.__init__ = original


# ── Shared Tk harness ─────────────────────────────────────────────────────
# Lives here rather than in each test module: review run 11 replaced the
# suite's inspect.getsource assertions with tests that drive real widgets,
# and both GUI modules need the same root and the same tree walker.

@pytest.fixture
def tk_root():
    """A real Tk root, mapped but parked off-screen.

    Mapped rather than withdrawn on purpose: Tk silently drops
    ``event_generate`` key events on non-viewable windows, and several tests
    below press real keys.  Skips instead of erroring when tkinter imports but
    no display is actually usable.
    """
    if not HAS_TKINTER:
        pytest.skip("needs real tkinter")
    import tkinter as tk
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"no usable display: {exc}")
    root.geometry("480x360-4000-4000")
    root.update()
    try:
        yield root
    finally:
        try:
            root.destroy()
        except tk.TclError:
            pass


@pytest.fixture(scope="session")
def qcx_sample(tmp_path_factory):
    """One real password-mode .qcx, shared by every test that needs a loaded
    decryptor.  Encrypting is Argon2id-bound, so pay for it once per session."""
    d = tmp_path_factory.mktemp("qcx_sample")
    src = d / "data.bin"
    src.write_bytes(b"hello decrypt" * 200)
    out = d / "data.qcx"
    with open(out, "wb") as f:
        offset = f.tell()
        meta = cc.encrypt_single_streaming(str(src), f, "s3cr3t-testpad",
                                           filename="data.bin")
        meta["payload_offset"] = offset
        blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
        f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
    return str(out), meta


def _widget_texts(widget, out=None):
    """Every non-empty ``-text`` option in the tree below ``widget``, so a test
    can assert on what the UI renders rather than on how it was built."""
    out = [] if out is None else out
    try:
        text = widget.cget("text")
    except Exception:          # Frame/Canvas/… simply have no -text option
        text = ""
    if text:
        out.append(str(text))
    for child in widget.winfo_children():
        _widget_texts(child, out)
    return out


# ── Parallel execution ────────────────────────────────────────────────────
# The suite parallelises with `-n auto --dist loadgroup`, but Tk does not:
# the macOS window server is process-external shared state, and running Tk in
# several workers at once makes focus and key delivery nondeterministic.
# Measured: 29 GUI failures under plain `-n auto`, all of them passing
# serially — keyboard activation, arrow-key selection, drop-hint rendering.
#
# `loadgroup` sends every test carrying the same xdist_group to ONE worker,
# so Tk stays effectively serial while the ~700 non-GUI tests spread out.
# Applied here rather than by hand so a new GUI test cannot forget it.

def _touches_tk(item) -> bool:
    """Whether this test can end up talking to the window server.

    Detected rather than listed: an explicit module list missed
    test_entrypoints and test_integration, which import tkinter without using
    the shared fixture, and their windows contended with the GUI worker's.
    Any module that imported tkinter under any alias counts.
    """
    if item.get_closest_marker("requires_tkinter"):
        return True
    if "tk_root" in getattr(item, "fixturenames", ()):
        return True
    module = getattr(item, "module", None)
    if module is None:
        return False
    tkinter = sys.modules.get("tkinter")
    if tkinter is not None:
        for value in vars(module).values():
            if value is tkinter:
                return True
    # Module globals are not enough: test_decryptor_ui imports tkinter inside
    # its fixtures, so nothing tkinter-shaped is ever bound at module level
    # and 17 of its tests escaped the split into the parallel pass. Fall back
    # to the source text, cached per file.
    path = getattr(module, "__file__", None)
    if path:
        return _module_mentions_tkinter(path)
    return False


@functools.lru_cache(maxsize=None)
def _module_mentions_tkinter(path: str) -> bool:
    try:
        return "tkinter" in pathlib.Path(path).read_text()
    except OSError:
        return False


#: Whether this process collected any GUI test. Non-GUI xdist workers must
#: never import tkinter — see the find_spec note at the top of this file.
_SESSION_HAS_GUI = False


def pytest_collection_modifyitems(items):
    global _SESSION_HAS_GUI
    """Mark every Tk-touching test `gui`, so the gate can split the run.

    Two passes beat one clever command here. `--dist loadgroup` keeps Tk on a
    single worker, but a run of ~1,600 GUI tests on that worker still ended
    with the workers dead and the controller waiting (measured: 48 minutes at
    0% CPU, no workers alive). A plain split is deterministic and each half is
    independently debuggable:

        pytest -m "not gui" -n auto     # ~600 tests, parallel
        pytest -m gui                   # Tk, serial
    """
    for item in items:
        if _touches_tk(item):
            item.add_marker(pytest.mark.gui)
            _SESSION_HAS_GUI = True
