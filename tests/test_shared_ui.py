"""Behavioural tests for ``quantacrypt.ui.shared`` — the design system layer.

Every assertion here is about an observable effect: the text a widget ends up
showing, the colour it ends up wearing, the argv handed to the file manager,
the bytes left on disk, the value a dialog returns.  Nothing asserts on source
text, and nothing asserts only that a mock was called when the effect itself
is visible.

Tk widgets need a real display, so the widget classes are marked
``@requires_tkinter``; the pure helpers (sizes, recents, prefs, platform
mapping) run headless.
"""

import errno
import gc
import importlib.util
import json
import os
import queue
import subprocess
import sys
import threading
import time as _time

import pytest

from tests.conftest import HAS_TKINTER, _widget_texts, requires_tkinter

from quantacrypt.ui import shared
from quantacrypt.ui.shared import (
    C, F, ICON, SP, AppPrefs, ClipboardTimer, FileCard, FlatButton,
    PasswordStrengthBar, RecentFiles, RecentVolumes, SegmentedControl,
    StagedProgressBar, WizardSteps, accel, alert, bind_context_menu,
    bind_shortcut, card, confirm, fmt_size, kv_row, reveal_path, rule,
    safe_after, section_label, styled_entry, write_new_private_file,
)

if HAS_TKINTER:
    import tkinter as tk


# ── helpers ──────────────────────────────────────────────────────────────────

def _pump_until(widget, predicate, timeout=5.0):
    """Run a real Tk main loop until ``predicate`` holds.

    A plain ``update()`` spin is not enough for anything that hands work back
    from a thread: tkinter only accepts calls from a worker while the main
    thread is actually inside ``mainloop()``, so otherwise the worker's
    ``after()`` raises RuntimeError and ``safe_after`` drops the hop.
    """
    root = widget.winfo_toplevel()
    deadline = _time.monotonic() + timeout
    state = {"ok": False, "exc": None}

    def _check():
        try:
            if predicate():
                state["ok"] = True
                root.quit()
                return
        except Exception as exc:                  # surface it after the loop
            state["exc"] = exc
            root.quit()
            return
        if _time.monotonic() > deadline:
            root.quit()
            return
        root.after(10, _check)

    root.after(1, _check)
    root.mainloop()
    if state["exc"] is not None:
        raise state["exc"]
    return state["ok"]


class _FastIdleQueue(queue.Queue):
    """The scoring queue, with a shorter idle timeout.

    The real worker parks for five seconds before giving up, which would
    leave one live thread per test.  Those threads reference their widget,
    and a garbage collection running inside one of them can free a previous
    test's Tcl interpreter from the wrong thread — which aborts the process
    instead of raising.  Shortening the park (not the behaviour) lets every
    worker be reaped with its test.
    """

    def get(self, block=True, timeout=None):
        if timeout is not None:
            timeout = min(timeout, 0.2)
        return super().get(block, timeout)


_LIVE_BARS = []
_EXTRA_THREADS = []


@pytest.fixture(autouse=True)
def _reap_scoring_workers():
    """No scoring thread outlives the test that started it."""
    try:
        yield
    finally:
        for bar in _LIVE_BARS:
            thread = bar._thread
            if thread is not None:
                thread.join(5)
        for thread in _EXTRA_THREADS:
            thread.join(5)
        _LIVE_BARS.clear()
        _EXTRA_THREADS.clear()
        gc.enable()
        gc.collect()


# ── leaked Tk variable traces ────────────────────────────────────────────────
# SRC DEFECT (reported, not fixed here — src/ belongs to another owner):
# ``SegmentedControl.__init__`` (src/quantacrypt/ui/shared.py:576) and
# ``PasswordStrengthBar.__init__`` (:923) each call
# ``variable.trace_add("write", lambda *_: self._refresh())`` and neither
# class overrides ``destroy()`` to take that trace off again.  The trace keeps
# the destroyed widget reachable and repaints it on the next write —
# reproduced: destroy a SegmentedControl, set its variable, and Tk reports
# ``TclError: invalid command name ".!segmentedcontrol.!label"`` out of the
# callback.  Any variable that outlives its widget (a mode StringVar owned by
# a wizard and handed to successive screens is exactly that) therefore carries
# one widget's tracer into the next.
#
# The tests below master every such variable on the per-test root, so today
# the tracer dies with the interpreter rather than crossing into another
# test — but only by accident of that choice.  ``_traced_var`` + the fixture
# make it deliberate: the leaked traces are removed after each test, while
# the interpreter is still alive, so no widget built by one test can ever be
# repainted by the next one's writes.
_TRACED_VARS = []


def _traced_var(master, value=""):
    """A StringVar for a widget that leaks its write trace (see above)."""
    var = tk.StringVar(master=master, value=value)
    _TRACED_VARS.append(var)
    return var


@pytest.fixture(autouse=True)
def _untrace_leaked_widget_variables(request):
    """Strip the write traces the shared widgets never remove."""
    # Pulled in here rather than declared as a parameter: taking tk_root
    # during THIS fixture's setup makes it finalise after us, which is the
    # only window in which trace_remove() still has an interpreter to talk to.
    if "tk_root" in request.fixturenames:
        request.getfixturevalue("tk_root")
    try:
        yield
    finally:
        for var in _TRACED_VARS:
            try:
                for mode, cbname in var.trace_info():
                    var.trace_remove(mode, cbname)
            except Exception:
                pass          # the window (and its interpreter) already went
        _TRACED_VARS.clear()


def _new_strength_bar(tk_root, value=""):
    # Tk widgets are reference cycles, so a destroyed root is freed by the
    # collector rather than by refcounting — and a collection that happens to
    # run inside the scoring worker frees the Tcl interpreter from the wrong
    # thread, which aborts the process instead of raising.  No collections
    # while a worker can be running; the reaper turns it back on.
    gc.disable()
    var = _traced_var(tk_root, value)
    bar = PasswordStrengthBar(tk_root, var)
    bar._queue = _FastIdleQueue()
    _LIVE_BARS.append(bar)
    bar.pack(fill="x", padx=10)
    tk_root.update()
    return bar, var


def _spawn_worker(bar):
    thread = threading.Thread(target=bar._worker_loop, daemon=True)
    _EXTRA_THREADS.append(thread)
    thread.start()
    return thread


# Every "what does the UI actually say" assertion goes through the shared
# tree walker from conftest.
_texts = _widget_texts


def _canvas_colours(cv, kind):
    """Fill colours of every ``kind`` item on a canvas, in creation order."""
    return [cv.itemcget(i, "fill") for i in cv.find_all() if cv.type(i) == kind]


def _load_shared_for(platform, block=()):
    """Execute shared.py again under a faked ``sys.platform``.

    The font / modifier / "reveal" label mapping and the optional-dependency
    probe are all decided at import time, so the only way to test the Windows
    and Linux arms from a macOS runner — or the no-zxcvbn arm on a machine
    that has it — is to run the module body again.  The result is deliberately
    NOT registered in ``sys.modules``: the live module and every class
    identity stay untouched.  ``block`` names modules that must appear
    missing (a None entry in sys.modules is what makes an import raise).
    """
    real = sys.platform
    saved = {name: sys.modules.get(name, "absent") for name in block}
    spec = importlib.util.spec_from_file_location(
        f"_shared_probe_{platform}", shared.__file__)
    mod = importlib.util.module_from_spec(spec)
    sys.platform = platform
    for name in block:
        sys.modules[name] = None
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.platform = real
        for name, prev in saved.items():
            if prev == "absent":
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prev
    return mod


# ── module-level design tokens ───────────────────────────────────────────────

class TestPlatformMapping:
    """The font family, keyboard modifier and "reveal" verb are chosen at
    import time from sys.platform; all three arms must be self-consistent."""

    def test_darwin_uses_menlo_command_and_finder(self):
        m = _load_shared_for("darwin")
        assert (m.UI, m.MONO) == (".AppleSystemUIFont", "Menlo")
        assert (m.MOD, m.MOD_LABEL) == ("Command", "⌘")
        assert m.REVEAL_LABEL == "Show in Finder"
        assert m.accel("O") == "⌘O"

    def test_windows_uses_segoe_consolas_and_ctrl(self):
        m = _load_shared_for("win32")
        assert (m.UI, m.MONO) == ("Segoe UI", "Consolas")
        assert (m.MOD, m.MOD_LABEL) == ("Control", "Ctrl+")
        assert m.REVEAL_LABEL == "Show in folder"
        assert m.accel("S") == "Ctrl+S"

    def test_linux_uses_dejavu_and_ctrl(self):
        m = _load_shared_for("linux")
        assert (m.UI, m.MONO) == ("DejaVu Sans", "DejaVu Sans Mono")
        assert m.MOD == "Control"
        assert m.REVEAL_LABEL == "Show in folder"

    def test_the_module_imports_without_the_optional_strength_extra(self):
        """zxcvbn is an optional extra: without it the module must still
        import and fall back to its own estimator."""
        m = _load_shared_for(sys.platform, block=("zxcvbn",))
        assert m._zxcvbn_fn is None
        # …and the fallback estimator is what actually scores: six lowercase
        # letters = 6 × log2(26) = 28.2 bits, the first value in the "Fair"
        # band.  ``_score`` only reaches into ``self`` for the label scale, so
        # the class stands in for an instance and no Tk root is needed.
        assert m.PasswordStrengthBar._score(
            m.PasswordStrengthBar, "abcdef") == (2, "Fair", "")
        assert shared._zxcvbn_fn is not None, "the live module is untouched"

    def test_every_font_uses_the_platform_families(self):
        """A hard-coded family silently turns proportional on macOS — the
        whole reason the scale is built from UI/MONO rather than literals."""
        for name, spec in F.items():
            assert spec[0] in (shared.UI, shared.MONO), name
        assert F["mono"][0] == shared.MONO and F["body"][0] == shared.UI

    def test_accel_passes_the_key_through_verbatim(self):
        assert accel("") == shared.MOD_LABEL
        assert accel("Return") == f"{shared.MOD_LABEL}Return"

    def test_spacing_scale_is_monotonic(self):
        vals = [SP[k] for k in ("xs", "s", "m", "l", "xl", "xxl")]
        assert vals == sorted(vals) and vals[0] > 0

    def test_icons_are_single_glyphs_not_colour_emoji(self):
        for k, v in ICON.items():
            assert len(v) == 1, k
            assert not (0x1F300 <= ord(v) <= 0x1FAFF), f"{k} is a colour emoji"


# ── fmt_size ─────────────────────────────────────────────────────────────────

class TestFmtSize:
    """One size vocabulary for every label: decimal units, as Finder and the
    native shell show them (run 13 F-034), one decimal place."""

    @pytest.mark.parametrize("n,expected", [
        (0, "0 B"),
        (1, "1 B"),
        (999, "999 B"),             # last byte before the KB boundary
        (1000, "1.0 KB"),           # first KB
        (999_999, "1000.0 KB"),     # last byte before the MB boundary
        (1_000_000, "1.0 MB"),
        (999_999_999, "1000.0 MB"),
        (1_000_000_000, "1.0 GB"),
        (5_000_000_000, "5.0 GB"),
        # GB is the top of the scale on purpose — a terabyte reads as 1000 GB
        # rather than growing a unit nobody in this app has a label width for.
        (1_000_000_000_000, "1000.0 GB"),
    ])
    def test_boundaries(self, n, expected):
        assert fmt_size(n) == expected

    def test_thousands_separator_only_below_a_kilobyte(self):
        assert fmt_size(999) == "999 B"
        assert "," not in fmt_size(2048)

    def test_a_nonsense_size_is_rendered_rather_than_raising(self):
        """BAD input: os.path.getsize() on a special file can come back
        negative.  A results screen must still render a string."""
        assert fmt_size(-1) == "-1 B"


# ── write_new_private_file ───────────────────────────────────────────────────

class TestWriteNewPrivateFile:
    """Key material must never land on top of an existing file, must be
    unreadable by other users, and must give up rather than loop forever."""

    def test_fresh_name_is_used_verbatim_and_is_0600(self, tmp_path):
        p = str(tmp_path / "shares.txt")
        out, renamed = write_new_private_file(p, "share-1\nshare-2\n")
        assert (out, renamed) == (p, False)
        assert os.stat(out).st_mode & 0o777 == 0o600
        assert open(out, encoding="utf-8").read() == "share-1\nshare-2\n"

    def test_existing_file_is_never_overwritten(self, tmp_path):
        p = str(tmp_path / "shares.txt")
        write_new_private_file(p, "original")
        out, renamed = write_new_private_file(p, "second")
        assert renamed is True and os.path.basename(out) == "shares_2.txt"
        assert open(p, encoding="utf-8").read() == "original"
        assert open(out, encoding="utf-8").read() == "second"

    def test_numbering_keeps_the_extension_and_climbs(self, tmp_path):
        p = str(tmp_path / "a.shares.txt")
        names = [os.path.basename(write_new_private_file(p, str(i))[0])
                 for i in range(4)]
        assert names == ["a.shares.txt", "a.shares_2.txt",
                         "a.shares_3.txt", "a.shares_4.txt"]

    def test_extensionless_and_dotfile_names(self, tmp_path):
        p = str(tmp_path / "keys")
        write_new_private_file(p, "1")
        assert os.path.basename(write_new_private_file(p, "2")[0]) == "keys_2"
        d = str(tmp_path / ".secret")
        write_new_private_file(d, "1")
        # splitext treats a leading dot as the stem, not an extension
        assert os.path.basename(write_new_private_file(d, "2")[0]) == ".secret_2"

    def test_unicode_and_spaces_and_quotes_in_the_name(self, tmp_path):
        p = str(tmp_path / "my shares 'x' \"y\" — ünïcode.txt")
        out, renamed = write_new_private_file(p, "ünïcode payload ✓")
        assert (out, renamed) == (p, False)
        assert open(out, encoding="utf-8").read() == "ünïcode payload ✓"
        out2, renamed2 = write_new_private_file(p, "again")
        assert renamed2 is True and out2.endswith("ünïcode_2.txt")

    def test_dangling_symlink_is_skipped_rather_than_reused(self, tmp_path):
        p = str(tmp_path / "a.txt")
        os.symlink(str(tmp_path / "nowhere"), p)
        out, renamed = write_new_private_file(p, "x")
        assert renamed is True and os.path.basename(out) == "a_2.txt"
        assert os.path.islink(p) and not os.path.exists(p)

    def test_a_name_that_appears_between_probe_and_open_is_skipped(
            self, tmp_path, monkeypatch):
        """O_EXCL is the real guard; the lexists() probe is only a fast path.
        A racing writer must cost the caller the name, never the contents."""
        real_open = os.open
        target = str(tmp_path / "k.txt")

        def racing_open(path, flags, mode=0o777, *a, **k):
            if path == target:
                raise FileExistsError(errno.EEXIST, "raced", path)
            return real_open(path, flags, mode, *a, **k)

        monkeypatch.setattr(os, "open", racing_open)
        out, renamed = write_new_private_file(target, "payload")
        assert renamed is True and os.path.basename(out) == "k_2.txt"
        assert not os.path.exists(target), "no partial file at the raced name"
        assert open(out, encoding="utf-8").read() == "payload"

    def test_gives_up_after_the_cap_without_writing_anything(self, tmp_path):
        p = str(tmp_path / "a.txt")
        for n in [None] + list(range(2, shared._MAX_NAME_ATTEMPTS + 1)):
            name = "a.txt" if n is None else f"a_{n}.txt"
            (tmp_path / name).write_text("taken")
        before = sorted(os.listdir(tmp_path))
        with pytest.raises(FileExistsError) as exc:
            write_new_private_file(p, "never written")
        assert exc.value.errno == errno.EEXIST
        assert str(shared._MAX_NAME_ATTEMPTS) in str(exc.value)
        assert sorted(os.listdir(tmp_path)) == before
        assert all((tmp_path / n).read_text() == "taken" for n in before)

    def test_the_last_free_slot_below_the_cap_still_works(self, tmp_path):
        """n-1 of the cap: 98 taken names leaves exactly one usable slot."""
        p = str(tmp_path / "a.txt")
        (tmp_path / "a.txt").write_text("taken")
        for n in range(2, shared._MAX_NAME_ATTEMPTS):
            (tmp_path / f"a_{n}.txt").write_text("taken")
        out, renamed = write_new_private_file(p, "last")
        assert os.path.basename(out) == f"a_{shared._MAX_NAME_ATTEMPTS}.txt"
        assert renamed is True

    def test_missing_directory_propagates_rather_than_renaming(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            write_new_private_file(str(tmp_path / "no" / "such" / "a.txt"), "x")
        assert not os.path.exists(tmp_path / "no")

    def test_an_unwritable_directory_propagates_and_writes_nothing(self, tmp_path):
        """BAD path: only FileExistsError means "try the next name".  A
        permission failure must surface to the caller on the first attempt —
        not be mistaken for a taken name and retried 99 times — and must leave
        the directory exactly as it found it."""
        if os.geteuid() == 0:
            pytest.skip("root ignores the directory mode")
        d = tmp_path / "locked"
        d.mkdir()
        (d / "keep.txt").write_text("existing")
        os.chmod(d, 0o500)
        try:
            with pytest.raises(PermissionError) as exc:
                write_new_private_file(str(d / "shares.txt"), "secret")
            assert exc.value.errno == errno.EACCES
            assert os.path.basename(exc.value.filename) == "shares.txt", \
                "it gave up on the first name rather than walking the numbers"
            assert sorted(os.listdir(d)) == ["keep.txt"]
            assert (d / "keep.txt").read_text() == "existing"
        finally:
            os.chmod(d, 0o700)

    def test_empty_text_still_creates_a_0600_file(self, tmp_path):
        out, renamed = write_new_private_file(str(tmp_path / "e.txt"), "")
        assert renamed is False and os.path.getsize(out) == 0
        assert os.stat(out).st_mode & 0o777 == 0o600

    def test_the_share_is_fsynced_before_the_file_is_closed(self, tmp_path,
                                                            monkeypatch):
        """The file is the only copy of the key: it has to be on the disk,
        not in a page cache a power cut would drop."""
        synced = []
        real_fsync = os.fsync

        def _spy(fd):
            synced.append((os.fstat(fd).st_ino, os.fstat(fd).st_size))
            real_fsync(fd)

        monkeypatch.setattr(os, "fsync", _spy)
        out, _ = write_new_private_file(str(tmp_path / "a.txt"), "share-1")
        # One sync, on this file, after the share was flushed into it.
        assert synced == [(os.stat(out).st_ino, len("share-1"))]


# ── safe_after ───────────────────────────────────────────────────────────────

class _FakeWidget:
    def __init__(self, exists=True, raise_on_after=None):
        self.exists = exists
        self.raise_on_after = raise_on_after
        self.queued = []

    def after(self, delay, fn):
        if self.raise_on_after is not None:
            raise self.raise_on_after
        self.queued.append((delay, fn))

    def winfo_exists(self):
        return self.exists


class TestSafeAfter:
    """A worker hand-back must never crash the worker: neither a non-threaded
    Tcl, nor a window the user already closed, nor a widget that dies between
    scheduling and running."""

    def test_hop_is_scheduled_with_the_requested_delay(self):
        w = _FakeWidget()
        calls = []
        safe_after(w, lambda: calls.append("ran"), 250)
        assert [d for d, _ in w.queued] == [250]
        assert calls == [], "the hop must not run inline"
        w.queued[0][1]()
        assert calls == ["ran"]

    def test_callback_is_skipped_once_the_widget_is_gone(self):
        w = _FakeWidget()
        calls = []
        safe_after(w, lambda: calls.append("ran"))
        w.exists = False
        w.queued[0][1]()
        assert calls == []

    def test_tclerror_from_the_callback_is_contained(self):
        """A widget that dies mid-callback raises TclError from inside the
        hop; swallowing it is the documented contract."""
        import tkinter as _tk
        ran = []
        w = _FakeWidget()
        safe_after(w, lambda: (_ for _ in ()).throw(_tk.TclError("bad window")))
        w.queued[0][1]()
        safe_after(w, lambda: ran.append("next"))
        w.queued[1][1]()
        assert ran == ["next"], "the helper is still usable afterwards"

    def test_non_threaded_tcl_runtimeerror_is_swallowed(self):
        # Not raising IS the contract here (see the docstring on safe_after):
        # a worker thread has nobody to catch for it.  The assertions pin the
        # other half — the hop is dropped rather than run on the worker.
        w = _FakeWidget(raise_on_after=RuntimeError("main thread is not in main loop"))
        safe_after(w, lambda: (_ for _ in ()).throw(AssertionError("must not run")))
        assert w.queued == []
        w.raise_on_after = None                # …and the helper still works after
        ran = []
        safe_after(w, lambda: ran.append("ok"))
        w.queued[0][1]()
        assert ran == ["ok"]

    def test_destroyed_window_tclerror_is_swallowed(self):
        # Same documented contract, for the window-already-closed case.
        import tkinter as _tk
        w = _FakeWidget(raise_on_after=_tk.TclError("bad window path name"))
        safe_after(w, lambda: (_ for _ in ()).throw(AssertionError("must not run")))
        assert w.queued == []

    def test_a_non_tcl_error_from_the_callback_still_propagates(self):
        """Only Tk teardown is swallowed — a real bug in the hand-back must
        not be hidden."""
        w = _FakeWidget()
        safe_after(w, lambda: (_ for _ in ()).throw(ValueError("real bug")))
        with pytest.raises(ValueError):
            w.queued[0][1]()


# ── reveal_path ──────────────────────────────────────────────────────────────

class TestRevealPath:
    """Each platform gets the command that selects the file, and a missing
    handler is reported instead of failing silently."""

    def _spy(self, monkeypatch, boom=None):
        calls = []

        def fake_popen(argv, *a, **k):
            calls.append(argv)
            if boom is not None:
                raise boom
            return object()

        monkeypatch.setattr(subprocess, "Popen", fake_popen)
        return calls

    def test_macos_reveals_and_selects(self, monkeypatch):
        calls = self._spy(monkeypatch)
        monkeypatch.setattr(sys, "platform", "darwin")
        assert reveal_path("/tmp/my file.qcx") is True
        assert calls == [["open", "-R", "--", "/tmp/my file.qcx"]]

    def test_macos_a_name_starting_with_a_dash_is_not_read_as_flags(
            self, monkeypatch):
        """A self-typed output name like -foo.qcx reaches ``open`` behind
        ``--`` so it is a file, not an option ``open`` rejects."""
        calls = self._spy(monkeypatch)
        monkeypatch.setattr(sys, "platform", "darwin")
        assert reveal_path("-foo.qcx") is True
        assert calls == [["open", "-R", "--", "-foo.qcx"]]

    def test_linux_hands_xdg_open_an_absolute_path(self, monkeypatch, tmp_path):
        """xdg-open refuses ``--`` outright, so a relative name is made
        absolute instead — an absolute path can never start with a dash."""
        (tmp_path / "-sub").mkdir()
        calls = self._spy(monkeypatch)
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.chdir(tmp_path)
        assert reveal_path("-sub") is True
        assert calls == [["xdg-open", str(tmp_path / "-sub")]]
        assert not calls[0][1].startswith("-")

    def test_windows_normalises_the_path_for_explorer(self, monkeypatch):
        calls = self._spy(monkeypatch)
        monkeypatch.setattr(sys, "platform", "win32")
        assert reveal_path("C:/Users/me/a.qcx") is True
        assert calls[0][:2] == ["explorer", "/select,"]
        assert calls[0][2] == os.path.normpath("C:/Users/me/a.qcx")

    def test_linux_opens_the_containing_folder_for_a_file(
            self, monkeypatch, tmp_path):
        f = tmp_path / "a.qcx"
        f.write_text("x")
        calls = self._spy(monkeypatch)
        monkeypatch.setattr(sys, "platform", "linux")
        assert reveal_path(str(f)) is True
        assert calls == [["xdg-open", str(tmp_path)]]

    def test_linux_opens_a_directory_directly(self, monkeypatch, tmp_path):
        calls = self._spy(monkeypatch)
        monkeypatch.setattr(sys, "platform", "linux")
        assert reveal_path(str(tmp_path)) is True
        assert calls == [["xdg-open", str(tmp_path)]]

    def test_missing_handler_reports_false(self, monkeypatch):
        calls = self._spy(monkeypatch, boom=FileNotFoundError("no xdg-open"))
        monkeypatch.setattr(sys, "platform", "linux")
        assert reveal_path("/tmp/a") is False
        assert len(calls) == 1, "it must have tried before giving up"


# ── app icon / notifications ─────────────────────────────────────────────────

class TestFindAppIcon:
    """The icon is looked for next to the frozen executable first, then in
    the source tree; anything else must return "" so notify() drops the
    contentImage rather than pointing osascript at nothing."""

    def test_bundle_resources_icns_wins(self, tmp_path, monkeypatch):
        res = tmp_path / "App.app" / "Contents" / "Resources"
        res.mkdir(parents=True)
        (res / "icon.icns").write_bytes(b"icns")
        (res / "icon.png").write_bytes(b"png")
        exe = tmp_path / "App.app" / "Contents" / "MacOS"
        exe.mkdir(parents=True)
        (exe / "quantacrypt").write_bytes(b"")
        monkeypatch.setattr(sys, "executable", str(exe / "quantacrypt"))
        assert shared._find_app_icon() == str(res / "icon.icns")

    def test_png_is_used_when_there_is_no_icns(self, tmp_path, monkeypatch):
        res = tmp_path / "App.app" / "Contents" / "Resources"
        res.mkdir(parents=True)
        (res / "icon.png").write_bytes(b"png")
        exe = tmp_path / "App.app" / "Contents" / "MacOS" / "quantacrypt"
        exe.parent.mkdir(parents=True)
        monkeypatch.setattr(sys, "executable", str(exe))
        assert shared._find_app_icon() == str(res / "icon.png")

    def test_source_checkout_falls_back_to_the_assets_folder(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "executable", str(tmp_path / "bin" / "python"))
        found = shared._find_app_icon()
        assert found.endswith(os.path.join("assets", "icon.png"))
        assert os.path.isfile(found)

    def test_nothing_anywhere_returns_empty_string(self, monkeypatch, tmp_path):
        fake_pkg = tmp_path / "pkg" / "ui" / "shared.py"
        fake_pkg.parent.mkdir(parents=True)
        monkeypatch.setattr(sys, "executable", str(tmp_path / "bin" / "python"))
        monkeypatch.setattr(shared, "__file__", str(fake_pkg))
        assert shared._find_app_icon() == ""


@requires_tkinter
class TestNotify:
    """notify() shells out to osascript; the strings it interpolates come
    from file names and error messages, so the escaping is the contract."""

    class _Proc:
        """What Popen hands back: a stdin that records the script.  No
        ``wait``/``communicate`` on purpose — notify() must not block on
        osascript, so calling either is a failure this double surfaces."""

        def __init__(self):
            self.script = ""
            self.closed = False
            self.stdin = self

        def write(self, s):
            assert not self.closed
            self.script += s

        def close(self):
            self.closed = True

    def _spy(self, monkeypatch, fail_first=False, fail_both=False):
        """Records ``(argv, proc)`` per launch; ``proc.script`` is what went
        down the pipe."""
        calls = []

        def fake_popen(argv, **k):
            proc = self._Proc()
            calls.append((argv, proc))
            if fail_both or (fail_first and len(calls) == 1):
                raise OSError("osascript missing")
            assert k.get("stdin") is subprocess.PIPE and k.get("text") is True
            return proc

        monkeypatch.setattr(subprocess, "Popen", fake_popen)
        return calls

    def _unfocused(self, tk_root, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(tk_root, "focus_displayof", lambda: None)
        monkeypatch.setattr(shared.tk.Tk, "_default_root", tk_root, raising=False)
        monkeypatch.setattr(shared, "_find_app_icon", lambda: "")

    def test_non_macos_never_shells_out(self, monkeypatch):
        calls = self._spy(monkeypatch)
        monkeypatch.setattr(sys, "platform", "linux")
        shared.notify("T", "M")
        assert calls == []

    def test_a_focused_window_suppresses_the_notification(self, tk_root, monkeypatch):
        calls = self._spy(monkeypatch)
        self._unfocused(tk_root, monkeypatch)
        monkeypatch.setattr(tk_root, "focus_displayof", lambda: tk_root)
        shared.notify("Done", "All good")
        assert calls == [], "no banner while the user is looking at the window"

    def test_unfocused_delivers_a_jxa_notification(self, tk_root, monkeypatch):
        calls = self._spy(monkeypatch)
        self._unfocused(tk_root, monkeypatch)
        shared.notify("Encrypted", "vault.qcx is ready")
        assert len(calls) == 1
        argv, proc = calls[0]
        assert argv == ["osascript", "-l", "JavaScript", "-"]
        script = proc.script
        assert 'n.title = "Encrypted";' in script
        assert 'n.informativeText = "vault.qcx is ready";' in script
        assert "NSUserNotificationDefaultSoundName" in script
        assert "contentImage" not in script      # no icon file was found
        assert "deliverNotification(n)" in script
        assert proc.closed, "stdin is closed so osascript sees EOF and runs"

    def test_the_file_name_never_travels_in_argv(self, tk_root, monkeypatch):
        """argv is readable by every local process through ``ps``; what was
        encrypted, decrypted or mounted goes down the pipe instead, on both
        transports."""
        calls = self._spy(monkeypatch, fail_first=True)
        self._unfocused(tk_root, monkeypatch)
        shared.notify("Decrypted", "tax-return-2025.pdf is ready")
        assert len(calls) == 2
        for argv, proc in calls:
            assert not any("tax-return-2025" in part for part in argv)
        assert "tax-return-2025.pdf" in calls[1][1].script

    def test_a_broken_focus_probe_does_not_block_the_banner(self, tk_root, monkeypatch):
        """The probe is a nicety; if Tk is mid-teardown the banner still goes."""
        calls = self._spy(monkeypatch)
        self._unfocused(tk_root, monkeypatch)
        monkeypatch.setattr(tk_root, "focus_displayof",
                            lambda: (_ for _ in ()).throw(shared.tk.TclError("gone")))
        shared.notify("T", "M")
        assert len(calls) == 1

    def test_no_default_root_still_notifies(self, tk_root, monkeypatch):
        calls = self._spy(monkeypatch)
        self._unfocused(tk_root, monkeypatch)
        monkeypatch.setattr(shared.tk.Tk, "_default_root", None, raising=False)
        shared.notify("T", "M")
        assert len(calls) == 1

    def test_sound_can_be_suppressed(self, tk_root, monkeypatch):
        calls = self._spy(monkeypatch)
        self._unfocused(tk_root, monkeypatch)
        shared.notify("T", "M", sound=False)
        assert "soundName" not in calls[0][1].script

    def test_icon_is_attached_when_one_is_found(self, tk_root, monkeypatch):
        calls = self._spy(monkeypatch)
        self._unfocused(tk_root, monkeypatch)
        monkeypatch.setattr(shared, "_find_app_icon", lambda: '/Apps/My "App"/icon.png')
        shared.notify("T", "M")
        script = calls[0][1].script
        assert 'initByReferencingFile("/Apps/My \\"App\\"/icon.png")' in script
        assert '{forKey: "contentImage"}' in script

    def test_quotes_backslashes_and_newlines_are_escaped_for_js(
            self, tk_root, monkeypatch):
        calls = self._spy(monkeypatch)
        self._unfocused(tk_root, monkeypatch)
        shared.notify('He said "hi" \\ bye', "line1\r\nline2")
        script = calls[0][1].script
        assert 'n.title = "He said \\"hi\\" \\\\ bye";' in script
        assert 'n.informativeText = "line1\\nline2";' in script
        assert "\r" not in script and "\n" in script   # only the literal \n pair survives

    def test_jxa_failure_falls_back_to_applescript(self, tk_root, monkeypatch):
        calls = self._spy(monkeypatch, fail_first=True)
        self._unfocused(tk_root, monkeypatch)
        shared.notify("Title", "Body")
        assert len(calls) == 2
        argv, proc = calls[1]
        assert argv == ["osascript", "-"]
        assert proc.script == ('display notification "Body" '
                               'with title "Title" sound name "Glass"')
        assert proc.closed

    def test_fallback_drops_the_sound_too(self, tk_root, monkeypatch):
        calls = self._spy(monkeypatch, fail_first=True)
        self._unfocused(tk_root, monkeypatch)
        shared.notify("Title", "Body", sound=False)
        assert calls[1][1].script == 'display notification "Body" with title "Title"'

    def test_a_pipe_that_breaks_falls_back_to_applescript(self, tk_root, monkeypatch):
        """osascript dying before it reads its stdin is the same failure as
        not launching: nothing was shown, so the fallback is still owed."""
        calls = self._spy(monkeypatch)
        self._unfocused(tk_root, monkeypatch)

        def _broken_write(s):
            raise BrokenPipeError("osascript exited")

        real_popen = subprocess.Popen

        def _popen(argv, **k):
            proc = real_popen(argv, **k)
            if len(calls) == 1:
                proc.stdin.write = _broken_write
            return proc

        monkeypatch.setattr(subprocess, "Popen", _popen)
        shared.notify("Title", "Body")
        assert [argv for argv, _ in calls] == [["osascript", "-l", "JavaScript", "-"],
                                               ["osascript", "-"]]
        assert calls[0][1].closed, "the broken pipe is still closed"

    def test_both_paths_failing_is_silent(self, tk_root, monkeypatch):
        """Documented contract: a notification is never worth crashing a
        finished encryption over."""
        calls = self._spy(monkeypatch, fail_both=True)
        self._unfocused(tk_root, monkeypatch)
        shared.notify("Title", "Body")
        assert len(calls) == 2, "both transports were tried, neither raised"


# ── data dir ─────────────────────────────────────────────────────────────────

class TestDataDir:
    """One per-user directory per platform, created on demand."""

    def _home(self, monkeypatch, tmp_path):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(os.path, "expanduser",
                            lambda p: p.replace("~", str(home), 1))
        return home

    def test_macos_uses_application_support(self, monkeypatch, tmp_path):
        home = self._home(monkeypatch, tmp_path)
        monkeypatch.setattr(sys, "platform", "darwin")
        d = shared._data_dir()
        assert d == str(home / "Library" / "Application Support" / "QuantaCrypt")
        assert os.path.isdir(d)

    def test_windows_uses_appdata(self, monkeypatch, tmp_path):
        self._home(monkeypatch, tmp_path)
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
        d = shared._data_dir()
        assert d == str(tmp_path / "roaming" / "QuantaCrypt") and os.path.isdir(d)

    def test_windows_without_appdata_falls_back_to_home(self, monkeypatch, tmp_path):
        home = self._home(monkeypatch, tmp_path)
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.delenv("APPDATA", raising=False)
        assert shared._data_dir() == str(home / "QuantaCrypt")

    def test_linux_honours_xdg_data_home(self, monkeypatch, tmp_path):
        self._home(monkeypatch, tmp_path)
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        assert shared._data_dir() == str(tmp_path / "xdg" / "QuantaCrypt")

    def test_linux_without_xdg_uses_local_share(self, monkeypatch, tmp_path):
        home = self._home(monkeypatch, tmp_path)
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        assert shared._data_dir() == str(home / ".local" / "share" / "QuantaCrypt")

    def test_calling_twice_is_idempotent(self, monkeypatch, tmp_path):
        self._home(monkeypatch, tmp_path)
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        assert shared._data_dir() == shared._data_dir()

    def test_the_directory_is_private_to_the_user(self, monkeypatch, tmp_path):
        """It holds the paths of every file decrypted and volume mounted;
        on a shared Linux host XDG_DATA_HOME is not necessarily 0700."""
        self._home(monkeypatch, tmp_path)
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        d = shared._data_dir()
        assert os.stat(d).st_mode & 0o777 == 0o700

    def test_a_directory_that_cannot_be_created_raises_here_and_is_absorbed_above(
            self, monkeypatch, tmp_path):
        """BAD path: _data_dir itself does not swallow — the recents layer
        above it is what turns an unusable data directory into an empty list
        rather than an exception in a wizard.  Both halves are asserted, since
        neither is any use without the other."""
        blocker = tmp_path / "blocked"
        blocker.write_text("i am a file, not a directory")
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setenv("APPDATA", str(blocker))
        with pytest.raises(OSError) as exc:
            shared._data_dir()
        assert exc.value.errno == errno.ENOTDIR
        monkeypatch.setattr(RecentFiles, "_PATH", "")
        assert RecentFiles.load() == []
        RecentFiles.add(str(tmp_path))          # and writing is survived too
        assert RecentFiles.load() == []


# ── RecentFiles / RecentVolumes ──────────────────────────────────────────────

@pytest.fixture
def recents(tmp_path, monkeypatch):
    """RecentFiles pointed at a throwaway store."""
    monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
    return tmp_path


def _touch(tmp_path, name):
    p = tmp_path / name
    p.write_text("x")
    return str(p)


class TestRecentFiles:
    """A most-recent-first list of files that still exist, capped at ten,
    that survives a corrupt or unwritable store without taking the app down."""

    def test_add_then_load_returns_the_path_and_a_timestamp(self, recents):
        p = _touch(recents, "a.qcx")
        before = _time.time()
        RecentFiles.add(p)
        loaded = RecentFiles.load()
        assert [path for path, _ in loaded] == [p]
        assert loaded[0][1]["path"] == p
        assert loaded[0][1]["ts"] >= before
        assert "mode" not in loaded[0][1], "no meta was supplied"

    def test_meta_is_stored_with_defaults_for_missing_keys(self, recents):
        p = _touch(recents, "a.qcx")
        RecentFiles.add(p, {"mode": "shamir"})
        entry = RecentFiles.load()[0][1]
        assert entry["mode"] == "shamir"
        assert entry["threshold"] == 0 and entry["total"] == 0

    def test_full_meta_round_trips(self, recents):
        p = _touch(recents, "a.qcx")
        RecentFiles.add(p, {"mode": "shamir", "threshold": 3, "total": 5})
        entry = RecentFiles.load()[0][1]
        assert (entry["mode"], entry["threshold"], entry["total"]) == ("shamir", 3, 5)

    def test_newest_first_and_re_adding_bumps_without_duplicating(self, recents):
        a, b = _touch(recents, "a.qcx"), _touch(recents, "b.qcx")
        RecentFiles.add(a)
        RecentFiles.add(b)
        assert [p for p, _ in RecentFiles.load()] == [b, a]
        RecentFiles.add(a)
        assert [p for p, _ in RecentFiles.load()] == [a, b]

    @pytest.mark.parametrize("n,expected", [(0, 0), (1, 1), (9, 9), (10, 10), (11, 10)])
    def test_the_list_is_capped_at_max_items(self, recents, n, expected):
        assert RecentFiles.MAX_ITEMS == 10
        paths = [_touch(recents, f"f{i}.qcx") for i in range(n)]
        for p in paths:
            RecentFiles.add(p)
        loaded = [p for p, _ in RecentFiles.load()]
        assert len(loaded) == expected
        if n:
            assert loaded[0] == paths[-1], "the newest entry always survives"
        if n > RecentFiles.MAX_ITEMS:
            assert paths[0] not in loaded, "the oldest entry is dropped"

    def test_deleted_files_are_filtered_and_the_store_is_rewritten(self, recents):
        a, b = _touch(recents, "a.qcx"), _touch(recents, "b.qcx")
        RecentFiles.add(a)
        RecentFiles.add(b)
        os.remove(a)
        assert [p for p, _ in RecentFiles.load()] == [b]
        on_disk = json.load(open(recents / "recent.json"))
        assert [e["path"] for e in on_disk] == [b], "the prune is persisted"

    def test_a_directory_is_not_a_recent_file(self, recents):
        d = recents / "adir.qcx"
        d.mkdir()
        RecentFiles.add(str(d))
        assert RecentFiles.load() == []

    def test_junk_entries_are_ignored_rather_than_crashing(self, recents):
        p = _touch(recents, "a.qcx")
        (recents / "recent.json").write_text(
            json.dumps(["a string", 42, None, {"no_path": 1}, {"path": p}]))
        assert [q for q, _ in RecentFiles.load()] == [p]

    def test_an_entry_whose_path_is_not_a_string_is_dropped_not_fatal(self, recents):
        """``os.path.isfile(None)`` is a TypeError, not a missing file; a
        hand-edited or half-restored store must never brick start-up."""
        p = _touch(recents, "a.qcx")
        (recents / "recent.json").write_text(json.dumps(
            [{"path": None}, {"path": []}, {"path": {}}, {"path": 0},
             {"path": 1.5}, {"path": p}]))
        assert [q for q, _ in RecentFiles.load()] == [p]
        assert json.load(open(recents / "recent.json")) == [{"path": p}], \
            "the junk is pruned from disk too"
        (recents / "recent.json").write_text(json.dumps([{"path": None}]))
        RecentFiles.add(p)                       # neither writer trips on it
        RecentFiles.remove(p)
        assert RecentFiles.load() == []

    def test_the_store_is_private_and_leaves_no_temp_file_behind(self, recents):
        p = _touch(recents, "a.qcx")
        RecentFiles.add(p)
        assert os.stat(recents / "recent.json").st_mode & 0o777 == 0o600
        assert [f for f in os.listdir(recents) if f.endswith(".tmp")] == []

    def test_a_write_that_fails_midway_keeps_the_previous_store(self, recents,
                                                               monkeypatch):
        """The dump goes to a temp file and is renamed over the store, so a
        crash mid-write can only ever lose the newest entry — never the list."""
        a, b = _touch(recents, "a.qcx"), _touch(recents, "b.qcx")
        RecentFiles.add(a)
        real_replace = os.replace

        def _no_replace(src, dst):
            if dst.endswith("recent.json"):
                raise OSError("disk full")
            return real_replace(src, dst)

        monkeypatch.setattr(os, "replace", _no_replace)
        RecentFiles.add(b)                           # survived, per the contract
        assert [p for p, _ in RecentFiles.load()] == [a]
        assert [f for f in os.listdir(recents) if f.endswith(".tmp")] == []

    def test_a_corrupt_store_reads_as_empty(self, recents):
        (recents / "recent.json").write_text("{not json")
        assert RecentFiles.load() == []
        p = _touch(recents, "a.qcx")
        RecentFiles.add(p)      # and the next write repairs it
        assert [q for q, _ in RecentFiles.load()] == [p]

    def test_a_json_object_instead_of_a_list_reads_as_empty(self, recents):
        (recents / "recent.json").write_text(json.dumps({"path": "/x"}))
        assert RecentFiles.load() == []

    def test_a_missing_store_reads_as_empty(self, recents):
        assert not os.path.exists(recents / "recent.json")
        assert RecentFiles.load() == []

    def test_remove_takes_out_one_entry_only(self, recents):
        a, b = _touch(recents, "a.qcx"), _touch(recents, "b.qcx")
        RecentFiles.add(a)
        RecentFiles.add(b)
        RecentFiles.remove(a)
        assert [p for p, _ in RecentFiles.load()] == [b]
        RecentFiles.remove("/not/in/the/list")   # a no-op, not an error
        assert [p for p, _ in RecentFiles.load()] == [b]

    def test_clear_empties_the_store(self, recents):
        RecentFiles.add(_touch(recents, "a.qcx"))
        RecentFiles.clear()
        assert RecentFiles.load() == []
        assert json.load(open(recents / "recent.json")) == []

    def test_an_unwritable_store_is_survived(self, tmp_path, monkeypatch):
        """The recents list is a convenience; losing it must never surface
        as an exception in a wizard."""
        monkeypatch.setattr(RecentFiles, "_PATH",
                            str(tmp_path / "no-such-dir" / "recent.json"))
        RecentFiles.add(_touch(tmp_path, "a.qcx"))
        assert RecentFiles.load() == []
        assert not os.path.exists(tmp_path / "no-such-dir")

    def test_paths_with_spaces_quotes_and_unicode_round_trip(self, recents):
        p = _touch(recents, "my 'file' \"x\" ünï.qcx")
        RecentFiles.add(p)
        assert [q for q, _ in RecentFiles.load()] == [p]

    def test_default_path_lands_in_the_data_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(RecentFiles, "_PATH", "")
        monkeypatch.setattr(shared, "_data_dir", lambda: str(tmp_path))
        assert RecentFiles._resolve_path() == str(tmp_path / "recent.json")
        RecentFiles.add(_touch(tmp_path, "a.qcx"))
        assert os.path.isfile(tmp_path / "recent.json")


class TestRecentVolumes:
    """Volumes keep their own list — a mounted .qcv must never show up in the
    decryptor's recents and vice versa."""

    def test_the_two_lists_use_different_files_and_do_not_mix(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr(RecentFiles, "_PATH", "")
        monkeypatch.setattr(RecentVolumes, "_PATH", "")
        monkeypatch.setattr(shared, "_data_dir", lambda: str(tmp_path))
        qcx = _touch(tmp_path, "a.qcx")
        qcv = _touch(tmp_path, "b.qcv")
        RecentFiles.add(qcx)
        RecentVolumes.add(qcv)
        assert [p for p, _ in RecentFiles.load()] == [qcx]
        assert [p for p, _ in RecentVolumes.load()] == [qcv]
        assert os.path.isfile(tmp_path / "recent.json")
        assert os.path.isfile(tmp_path / "recent-volumes.json")

    def test_clearing_volumes_leaves_the_file_list_alone(self, tmp_path, monkeypatch):
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "r.json"))
        monkeypatch.setattr(RecentVolumes, "_PATH", str(tmp_path / "v.json"))
        RecentFiles.add(_touch(tmp_path, "a.qcx"))
        RecentVolumes.add(_touch(tmp_path, "b.qcv"))
        RecentVolumes.clear()
        assert RecentVolumes.load() == []
        assert len(RecentFiles.load()) == 1


# ── AppPrefs ─────────────────────────────────────────────────────────────────

class TestAppPrefs:
    """A key/value scratchpad (dismissed-update tag and friends) that reads
    as empty rather than raising when the file is missing or garbage."""

    @pytest.fixture(autouse=True)
    def _store(self, tmp_path, monkeypatch):
        monkeypatch.setattr(AppPrefs, "_PATH", str(tmp_path / "prefs.json"))
        self.path = tmp_path / "prefs.json"

    def test_get_returns_the_default_before_anything_is_set(self):
        assert AppPrefs.get("dismissed") is None
        assert AppPrefs.get("dismissed", "v1.0") == "v1.0"

    def test_set_then_get_round_trips_through_disk(self):
        AppPrefs.set("dismissed", "v1.3.0")
        assert json.load(open(self.path)) == {"dismissed": "v1.3.0"}
        assert AppPrefs.get("dismissed") == "v1.3.0"

    def test_a_second_key_does_not_clobber_the_first(self):
        AppPrefs.set("a", 1)
        AppPrefs.set("b", [1, 2, {"c": True}])
        assert AppPrefs.get("a") == 1
        assert AppPrefs.get("b") == [1, 2, {"c": True}]

    def test_setting_the_same_key_overwrites(self):
        AppPrefs.set("a", 1)
        AppPrefs.set("a", 2)
        assert AppPrefs.get("a") == 2
        assert json.load(open(self.path)) == {"a": 2}

    def test_a_falsy_value_is_returned_not_replaced_by_the_default(self):
        AppPrefs.set("seen", False)
        assert AppPrefs.get("seen", "fallback") is False

    def test_corrupt_json_reads_as_empty_and_the_next_set_repairs_it(self):
        self.path.write_text("<<<not json>>>")
        assert AppPrefs.get("a", "d") == "d"
        AppPrefs.set("a", 1)
        assert AppPrefs.get("a") == 1

    def test_the_file_is_private_and_written_atomically(self, monkeypatch):
        AppPrefs.set("a", 1)
        assert os.stat(self.path).st_mode & 0o777 == 0o600
        assert [f for f in os.listdir(self.path.parent) if f.endswith(".tmp")] == []
        real_replace = os.replace
        monkeypatch.setattr(os, "replace", lambda s, d: (
            (_ for _ in ()).throw(OSError("disk full")) if d.endswith("prefs.json")
            else real_replace(s, d)))
        AppPrefs.set("a", 2)
        assert AppPrefs.get("a") == 1, "the old value survives a failed write"
        assert [f for f in os.listdir(self.path.parent) if f.endswith(".tmp")] == []

    def test_a_json_list_instead_of_an_object_reads_as_empty(self):
        self.path.write_text(json.dumps([1, 2, 3]))
        assert AppPrefs.get("a", "d") == "d"

    def test_an_unwritable_store_is_survived(self, tmp_path, monkeypatch):
        monkeypatch.setattr(AppPrefs, "_PATH", str(tmp_path / "nope" / "p.json"))
        AppPrefs.set("a", 1)
        assert AppPrefs.get("a", "d") == "d"      # nothing persisted, nothing raised

    def test_default_path_lands_in_the_data_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(AppPrefs, "_PATH", "")
        monkeypatch.setattr(shared, "_data_dir", lambda: str(tmp_path))
        assert AppPrefs._resolve_path() == str(tmp_path / "prefs.json")
        AppPrefs.set("k", "v")
        assert json.load(open(tmp_path / "prefs.json")) == {"k": "v"}


# ── Tk harness helpers ───────────────────────────────────────────────────────

def _focus(root, widget=None):
    """Give ``widget`` real keyboard focus, and confirm that it took.

    Tk drops ``event_generate`` key events on the floor when the application
    is not the focused one, and on a busy macOS runner ``focus_force`` does
    not always win on the first try — so retry until Tk agrees, rather than
    generating keys into the void.
    """
    target = widget or root
    deadline = _time.monotonic() + 3.0
    while _time.monotonic() < deadline:
        root.update()
        root.focus_force()
        target.focus_set()
        root.update()
        if str(root.tk.call("focus")) == str(target):
            return
        _time.sleep(0.02)
    pytest.skip("the window manager will not hand this process keyboard focus")


@pytest.fixture
def menus(monkeypatch):
    """Capture the popup menus bind_context_menu builds instead of posting
    them (tk_popup blocks on a real grab)."""
    posted = []
    monkeypatch.setattr(tk.Menu, "tk_popup",
                        lambda self, x, y, entry="": posted.append((self, x, y)))
    return posted


def _font(spec):
    """Tk's normalised form of a font tuple, as cget() returns it.

    A family containing a space comes back brace-quoted ("{DejaVu Sans} 13"),
    which macOS never shows because its family is ".AppleSystemUIFont" — so
    four of these assertions passed locally and failed on Linux CI.
    """
    family, rest = str(spec[0]), [str(p) for p in spec[1:]]
    if " " in family:
        family = "{" + family + "}"
    return " ".join([family] + rest)


def _menu_labels(menu):
    end = menu.index("end")
    if end is None:
        return []
    return ["--" if menu.type(i) == "separator" else menu.entrycget(i, "label")
            for i in range(end + 1)]


# ── bind_shortcut ────────────────────────────────────────────────────────────

@requires_tkinter
class TestBindShortcut:
    """One call must cover the platform modifier, both letter cases and (by
    default) Ctrl as well, so muscle memory from any platform works."""

    def test_platform_modifier_fires_the_handler(self, tk_root):
        e = tk.Entry(tk_root)
        e.pack()
        calls = []
        bind_shortcut(e, "o", lambda: calls.append("o"))
        _focus(tk_root, e)
        e.event_generate(f"<{shared.MOD}-o>", when="now")
        tk_root.update()
        assert calls == ["o"]

    def test_both_letter_cases_are_bound(self, tk_root):
        e = tk.Entry(tk_root)
        e.pack()
        calls = []
        bind_shortcut(e, "s", lambda: calls.append("s"))
        _focus(tk_root, e)
        e.event_generate(f"<{shared.MOD}-s>", when="now")
        e.event_generate(f"<{shared.MOD}-S>", when="now")
        tk_root.update()
        assert calls == ["s", "s"], "shift-held ⌘S must work too"

    def test_control_is_bound_alongside_the_platform_modifier(self, tk_root):
        e = tk.Entry(tk_root)
        e.pack()
        calls = []
        bind_shortcut(e, "w", lambda: calls.append("w"))
        _focus(tk_root, e)
        e.event_generate("<Control-w>", when="now")
        tk_root.update()
        assert calls == ["w"]

    def test_also_control_false_binds_only_the_platform_modifier(self, tk_root):
        """The contract is "only MOD", not "not Control".

        Where MOD *is* Control — every platform but macOS — the two are the
        same binding, so asserting Ctrl stays free was a macOS-only claim and
        failed on Linux CI.
        """
        e = tk.Entry(tk_root)
        e.pack()
        calls = []
        bind_shortcut(e, "q", lambda: calls.append("q"), also_control=False)
        _focus(tk_root, e)

        if shared.MOD != "Control":
            e.event_generate("<Control-q>", when="now")
            tk_root.update()
            assert calls == [], "Ctrl-Q must stay free when it is not the modifier"

        e.event_generate(f"<{shared.MOD}-q>", when="now")
        tk_root.update()
        assert calls == ["q"]

    def test_a_keysym_is_bound_as_one_sequence_not_two_cases(self, tk_root):
        e = tk.Entry(tk_root)
        e.pack()
        calls = []
        bind_shortcut(e, "Return", lambda: calls.append("ret"))
        _focus(tk_root, e)
        e.event_generate(f"<{shared.MOD}-Return>", when="now")
        tk_root.update()
        assert calls == ["ret"]
        assert e.bind(f"<{shared.MOD}-return>") == "", "no lower-cased variant"

    def test_the_event_is_consumed_so_the_widget_never_sees_the_key(self, tk_root):
        """The handler returns "break": without it ⌘A on an Entry would also
        run Tk's own class binding."""
        e = tk.Entry(tk_root)
        e.pack()
        after_widget = []
        e.bind_class("Entry", f"<{shared.MOD}-b>",
                     lambda ev: after_widget.append("class"), add="+")
        bind_shortcut(e, "b", lambda: None)
        _focus(tk_root, e)
        e.event_generate(f"<{shared.MOD}-b>", when="now")
        tk_root.update()
        assert after_widget == []

    def test_a_typod_keysym_is_rejected_instead_of_binding_nothing(self, tk_root):
        """BAD path: a keysym Tk does not know must blow up where the shortcut
        is written.  Silently binding nothing would ship a menu item with an
        accelerator printed next to it that never fires."""
        e = tk.Entry(tk_root)
        e.pack()
        with pytest.raises(tk.TclError, match="keysym"):
            bind_shortcut(e, "NotAKeysym", lambda: None)
        assert e.bind() == (), "nothing was left half-bound on the widget"

    def test_two_shortcuts_on_one_widget_stay_independent(self, tk_root):
        e = tk.Entry(tk_root)
        e.pack()
        calls = []
        bind_shortcut(e, "o", lambda: calls.append("open"))
        bind_shortcut(e, "n", lambda: calls.append("new"))
        _focus(tk_root, e)
        e.event_generate(f"<{shared.MOD}-n>", when="now")
        tk_root.update()
        assert calls == ["new"]


# ── bind_context_menu ────────────────────────────────────────────────────────

@requires_tkinter
class TestBindContextMenu:
    """The menu offered must match what the widget can actually do: no Cut or
    Paste on a read-only field, no Copy without a selection, no menu at all
    when every item would be disabled."""

    def _entry(self, tk_root, text="hello world", **kw):
        e = styled_entry(tk_root, **kw)
        e.pack()
        tk_root.update()
        if text:
            e.insert(0, text)
        tk_root.update()
        return e

    def test_entry_without_a_selection_offers_paste_and_select_all(
            self, tk_root, menus):
        e = self._entry(tk_root)
        e.event_generate("<Button-3>", x=3, y=3)
        tk_root.update()
        assert len(menus) == 1
        assert _menu_labels(menus[0][0]) == ["Paste", "--", "Select All"]

    def test_entry_with_a_selection_offers_cut_and_copy_first(self, tk_root, menus):
        e = self._entry(tk_root)
        e.select_range(0, 5)
        tk_root.update()
        e.event_generate("<Button-3>", x=3, y=3)
        tk_root.update()
        assert _menu_labels(menus[0][0]) == ["Cut", "Copy", "Paste", "--", "Select All"]

    def test_readonly_entry_offers_copy_only(self, tk_root, menus):
        e = self._entry(tk_root)
        e.select_range(0, 5)
        e.config(state="readonly")
        tk_root.update()
        e.event_generate("<Button-3>", x=3, y=3)
        tk_root.update()
        assert _menu_labels(menus[0][0]) == ["Copy", "--", "Select All"]

    def test_disabled_entry_without_a_selection_shows_no_menu(self, tk_root, menus):
        """Every entry would be suppressed, so posting an empty strip would
        just be a flicker under the cursor."""
        e = self._entry(tk_root, text="")
        e.config(state="disabled")
        tk_root.update()
        e.event_generate("<Button-3>", x=3, y=3)
        tk_root.update()
        assert menus == []

    def test_empty_editable_entry_offers_paste_but_not_select_all(
            self, tk_root, menus):
        e = self._entry(tk_root, text="")
        e.event_generate("<Button-3>", x=3, y=3)
        tk_root.update()
        assert _menu_labels(menus[0][0]) == ["Paste"]

    def test_text_widget_always_offers_select_all(self, tk_root, menus):
        t = tk.Text(tk_root, height=2)
        bind_context_menu(t)
        t.pack()
        t.insert("1.0", "some text")
        tk_root.update()
        t.event_generate("<Button-3>", x=3, y=3)
        tk_root.update()
        assert _menu_labels(menus[0][0]) == ["Paste", "--", "Select All"]
        t.tag_add("sel", "1.0", "1.4")
        tk_root.update()
        t.event_generate("<Button-3>", x=3, y=3)
        tk_root.update()
        assert _menu_labels(menus[1][0]) == ["Cut", "Copy", "Paste", "--", "Select All"]

    def test_a_failing_selection_probe_degrades_to_no_selection(
            self, tk_root, menus):
        """The probe is best-effort — a widget mid-teardown must still get a
        usable menu rather than an exception inside the event handler."""
        e = self._entry(tk_root)
        e.select_range(0, 5)
        e.selection_present = lambda: (_ for _ in ()).throw(tk.TclError("gone"))
        tk_root.update()
        e.event_generate("<Button-3>", x=3, y=3)
        tk_root.update()
        assert _menu_labels(menus[0][0]) == ["Paste", "--", "Select All"]

    def test_select_all_really_selects_the_entry_contents(self, tk_root, menus):
        e = self._entry(tk_root, text="pick me")
        e.event_generate("<Button-3>", x=3, y=3)
        tk_root.update()
        menu = menus[0][0]
        menu.invoke(_menu_labels(menu).index("Select All"))
        tk_root.update()
        assert e.selection_present() and e.selection_get() == "pick me"
        assert e.index("insert") == len("pick me")

    def test_select_all_really_selects_the_text_contents(self, tk_root, menus):
        t = tk.Text(tk_root, height=2)
        bind_context_menu(t)
        t.pack()
        t.insert("1.0", "line one\nline two")
        tk_root.update()
        t.event_generate("<Button-3>", x=3, y=3)
        tk_root.update()
        menu = menus[0][0]
        menu.invoke(_menu_labels(menu).index("Select All"))
        tk_root.update()
        assert t.get("sel.first", "sel.last") == "line one\nline two\n"

    def test_copy_puts_the_selection_on_the_clipboard(self, tk_root, menus):
        e = self._entry(tk_root, text="copy this")
        _focus(tk_root, e)
        e.select_range(0, 4)
        tk_root.update()
        e.event_generate("<Button-3>", x=3, y=3)
        tk_root.update()
        menu = menus[0][0]
        tk_root.clipboard_clear()
        menu.invoke(_menu_labels(menu).index("Copy"))
        tk_root.update()
        assert tk_root.clipboard_get() == "copy"

    def test_cut_removes_the_selection_from_the_entry(self, tk_root, menus):
        e = self._entry(tk_root, text="cut this")
        _focus(tk_root, e)
        e.select_range(0, 4)
        tk_root.update()
        e.event_generate("<Button-3>", x=3, y=3)
        tk_root.update()
        menu = menus[0][0]
        menu.invoke(_menu_labels(menu).index("Cut"))
        tk_root.update()
        assert e.get() == "this"

    def test_all_three_mouse_bindings_post_the_menu(self, tk_root, menus):
        """macOS fires Button-2 or Control-Button-1; X11/Windows Button-3."""
        e = self._entry(tk_root)
        for seq in ("<Button-2>", "<Control-Button-1>", "<Button-3>"):
            e.event_generate(seq, x=3, y=3)
            tk_root.update()
        assert len(menus) == 3

    def test_the_menu_is_posted_at_the_pointer(self, tk_root, menus):
        e = self._entry(tk_root)
        e.event_generate("<Button-3>", x=7, y=9)
        tk_root.update()
        _menu, x, y = menus[0]
        assert (x, y) == (e.winfo_rootx() + 7, e.winfo_rooty() + 9)

    def test_bind_context_menu_returns_the_widget_for_chaining(self, tk_root):
        e = tk.Entry(tk_root)
        assert bind_context_menu(e) is e


# ── card / kv_row / rule / section_label ─────────────────────────────────────

@requires_tkinter
class TestCard:
    """One card recipe: a bordered surface whose INNER frame is what callers
    pack into, so nobody retypes the border."""

    def test_returns_the_inner_frame_wrapped_in_a_bordered_outer(self, tk_root):
        inner = card(tk_root)
        tk_root.update()
        assert inner.master is inner.outer
        assert inner.outer.master is tk_root
        assert inner.outer.cget("bg") == C["surface"]
        assert inner.cget("bg") == C["surface"]
        assert str(inner.outer.cget("highlightbackground")) == C["border"]
        assert int(inner.outer.cget("highlightthickness")) == 1

    def test_default_padding_comes_from_the_spacing_scale(self, tk_root):
        inner = card(tk_root)
        tk_root.update()
        info = inner.pack_info()
        assert int(info["padx"]) == SP["m"] and int(info["pady"]) == SP["s"]
        assert info["fill"] == "both"

    def test_padding_is_overridable_and_kwargs_reach_the_outer_frame(self, tk_root):
        inner = card(tk_root, padx=0, pady=SP["xl"], width=200)
        tk_root.update()
        assert int(inner.pack_info()["padx"]) == 0
        assert int(inner.pack_info()["pady"]) == SP["xl"]
        assert int(inner.outer.cget("width")) == 200

    def test_content_packed_into_the_inner_frame_is_rendered(self, tk_root):
        inner = card(tk_root)
        inner.outer.pack()
        tk.Label(inner, text="Inside the card").pack()
        tk_root.update()
        assert _texts(inner.outer) == ["Inside the card"]


@requires_tkinter
class TestKvRow:
    """Label/value row for every metadata card: the value label is returned
    so callers can relabel it later."""

    def test_renders_both_halves_and_returns_the_value_label(self, tk_root):
        parent = tk.Frame(tk_root, bg=C["surface"])
        parent.pack()
        val = kv_row(parent, "Mode", "Password")
        tk_root.update()
        assert val.cget("text") == "Password"
        assert _texts(parent) == ["Mode", "Password"]

    def test_the_row_inherits_the_parent_background(self, tk_root):
        parent = tk.Frame(tk_root, bg=C["surface2"])
        parent.pack()
        val = kv_row(parent, "K", "V")
        tk_root.update()
        assert val.cget("bg") == C["surface2"]
        assert val.master.cget("bg") == C["surface2"]

    def test_label_width_and_wraplength_are_tunable(self, tk_root):
        parent = tk.Frame(tk_root, bg=C["bg"])
        parent.pack()
        val = kv_row(parent, "Key", "Value", label_width=4, wraplength=120, pady=0)
        tk_root.update()
        key_lbl = parent.winfo_children()[0].winfo_children()[0]
        assert int(key_lbl.cget("width")) == 4
        assert int(val.cget("wraplength")) == 120
        assert int(val.master.pack_info()["pady"]) == 0

    def test_a_very_long_unicode_value_is_kept_verbatim(self, tk_root):
        parent = tk.Frame(tk_root, bg=C["bg"])
        parent.pack()
        long = "ünïcode ✓ " * 200
        val = kv_row(parent, "Path", long)
        tk_root.update()
        assert val.cget("text") == long

    def test_the_returned_label_can_be_relabelled(self, tk_root):
        parent = tk.Frame(tk_root, bg=C["bg"])
        parent.pack()
        val = kv_row(parent, "Section", "PASSWORD")
        val.config(text="SHARES")
        tk_root.update()
        assert _texts(parent) == ["Section", "SHARES"]


@requires_tkinter
class TestRuleAndSectionLabel:
    """Hairlines and section headings — the two structural separators."""

    def test_rule_is_a_one_pixel_border_coloured_line(self, tk_root):
        f = rule(tk_root)
        tk_root.update()
        assert f.cget("bg") == C["border"]
        assert int(f.cget("height")) == 1
        assert int(f.pack_info()["pady"]) == 12 and f.pack_info()["fill"] == "x"

    def test_rule_colour_and_padding_are_overridable(self, tk_root):
        f = rule(tk_root, color=C["accent"], pady=0, padx=SP["l"])
        tk_root.update()
        assert f.cget("bg") == C["accent"]
        assert int(f.pack_info()["pady"]) == 0
        assert int(f.pack_info()["padx"]) == SP["l"]

    def test_section_label_returns_the_text_label_next_to_a_divider(self, tk_root):
        lbl = section_label(tk_root, "PASSWORD")
        tk_root.update()
        assert lbl.cget("text") == "PASSWORD"
        assert lbl.cget("fg") == C["text3"] and lbl.cget("font") == _font(F["small"])
        row = lbl.master
        divider = row.winfo_children()[1]
        assert int(divider.cget("height")) == 2
        assert divider.cget("bg") == C["border"]

    def test_section_label_can_be_relabelled_later(self, tk_root):
        lbl = section_label(tk_root, "PASSWORD", padx=0)
        lbl.config(text="SHARES")
        tk_root.update()
        assert _texts(lbl.master) == ["SHARES"]
        assert int(lbl.master.pack_info()["padx"]) == 0


@requires_tkinter
class TestStyledEntry:
    """Every text field in the app comes from here, so the theme and the
    right-click menu are attached exactly once."""

    def test_theme_tokens_are_applied(self, tk_root):
        e = styled_entry(tk_root)
        assert e.cget("bg") == C["surface2"]
        assert e.cget("fg") == C["text"]
        assert e.cget("insertbackground") == C["accent_text"]
        assert str(e.cget("relief")) == "flat"
        assert int(e.cget("highlightthickness")) == 1
        assert e.cget("font") == _font(F["body"])

    def test_caller_kwargs_reach_the_entry(self, tk_root):
        e = styled_entry(tk_root, show="•", width=12)
        assert e.cget("show") == "•" and int(e.cget("width")) == 12

    def test_the_context_menu_is_attached(self, tk_root, menus):
        e = styled_entry(tk_root)
        e.pack()
        e.insert(0, "x")
        tk_root.update()
        e.event_generate("<Button-3>", x=1, y=1)
        tk_root.update()
        assert len(menus) == 1


# ── confirm / alert ──────────────────────────────────────────────────────────

def _find_dialog(root, skip=()):
    """The newest Toplevel under ``root`` that is not one the test opened."""
    tops = [ch for ch in root.winfo_children()
            if isinstance(ch, tk.Toplevel) and ch not in skip]
    return tops[-1] if tops else None


def _dialog_buttons(win):
    return [w for w in win.winfo_children()[2].winfo_children()
            if isinstance(w, FlatButton)]


def _when_dialog(root, fn, skip=()):
    """Run ``fn(win)`` as soon as the modal dialog exists.

    ``_dialog`` blocks in ``wait_window()``, so every interaction has to be
    scheduled beforehand — and everything worth asserting has to be read off
    the window before it is destroyed.
    """
    state = {"tries": 0, "error": None}

    def _go():
        win = _find_dialog(root, skip)
        if win is None:
            state["tries"] += 1
            if state["tries"] > 300:      # never leave the suite wedged
                return
            root.after(10, _go)
            return
        try:
            fn(win)
        except Exception as exc:          # surfaced by the test, not by Tk
            state["error"] = exc
        finally:
            if win.winfo_exists():
                win.destroy()

    root.after(20, _go)
    return state


def _snapshot(win):
    """Everything a test wants to know about a dialog, read while it lives."""
    return {
        "title": win.title(),
        "texts": _texts(win),
        "buttons": [(b.cget("text"), b.cget("bg")) for b in _dialog_buttons(win)],
        "focus": win.focus_lastfor().cget("text"),
        "resizable": win.resizable(),
    }


def _press(root, label, cap=None, skip=()):
    """Schedule a click on the button carrying ``label``, snapshotting the
    dialog into ``cap`` first."""
    def _click(win):
        if cap is not None:
            cap.update(_snapshot(win))
        for b in _dialog_buttons(win):
            if b.cget("text") == label:
                b._fire()
                return
        raise AssertionError(f"no {label!r} button in {_texts(win)}")
    return _when_dialog(root, _click, skip)


@requires_tkinter
class TestConfirmDialog:
    """A themed modal that answers True/False, defaults to the safe button,
    and treats Escape and the close box as "no"."""

    def test_pressing_the_yes_button_returns_true(self, tk_root):
        state = _press(tk_root, "Continue")
        assert confirm(tk_root, "Delete?", "This cannot be undone.") is True
        assert state["error"] is None

    def test_pressing_the_no_button_returns_false(self, tk_root):
        _press(tk_root, "Cancel")
        assert confirm(tk_root, "Delete?", "This cannot be undone.") is False

    def test_escape_answers_with_the_last_button(self, tk_root):
        _when_dialog(tk_root, lambda win: win.event_generate("<Escape>"))
        assert confirm(tk_root, "Delete?", "Sure?") is False

    def test_closing_the_window_answers_with_the_last_button(self, tk_root):
        # WM_DELETE_WINDOW is wired straight to destroy(), which is what the
        # close box does.
        _when_dialog(tk_root, lambda win: win.destroy())
        assert confirm(tk_root, "Delete?", "Sure?") is False

    def test_title_message_and_buttons_are_all_rendered(self, tk_root):
        cap = {}
        _press(tk_root, "Unmount", cap)
        assert confirm(tk_root, "Unmount volume", "Files will be flushed.",
                       yes="Unmount", no="Keep mounted") is True
        assert cap["title"] == "Unmount volume"
        assert cap["texts"] == ["Unmount volume", "Files will be flushed.",
                                "Unmount", "Keep mounted"]
        assert cap["resizable"] == (False, False)

    def test_both_buttons_are_in_the_tab_order(self, tk_root):
        """_dialog only focus_set()s the default button; reaching the other
        one is Tab or nothing, and these two gate destructive actions."""
        cap = {}
        def _check(win):
            cap["ok"] = {b.cget("text"): win.tk.call("::tk::FocusOK", b._w)
                         for b in _dialog_buttons(win)}
            for b in _dialog_buttons(win):
                if b.cget("text") == "Cancel":
                    b._fire()
        _when_dialog(tk_root, _check)
        assert confirm(tk_root, "Delete?", "Sure?") is False
        assert cap["ok"] == {"Continue": 1, "Cancel": 1}

    def test_the_safe_button_holds_focus_by_default(self, tk_root):
        cap = {}
        _press(tk_root, "Cancel", cap)
        confirm(tk_root, "Delete?", "Sure?")
        assert cap["focus"] == "Cancel", "a stray Return must not destroy anything"

    def test_default_no_false_puts_focus_on_the_action(self, tk_root):
        cap = {}
        _press(tk_root, "Cancel", cap)
        confirm(tk_root, "Save?", "Keep going?", default_no=False)
        assert cap["focus"] == "Continue"

    def test_danger_paints_the_action_red_not_blue(self, tk_root):
        cap = {}
        _press(tk_root, "Cancel", cap)
        confirm(tk_root, "Erase?", "Gone for good.", danger=True)
        assert dict(cap["buttons"]) == {"Continue": C["error_fill"],
                                        "Cancel": C["surface2"]}

    def test_without_danger_the_action_is_the_accent_fill(self, tk_root):
        cap = {}
        _press(tk_root, "Cancel", cap)
        confirm(tk_root, "Proceed?", "OK?")
        assert dict(cap["buttons"])["Continue"] == C["accent"]

    def test_a_long_unicode_message_is_shown_verbatim(self, tk_root):
        cap = {}
        msg = "Ünïcode — " + "very long message " * 40
        _press(tk_root, "Cancel", cap)
        confirm(tk_root, "Title ✓", msg)
        assert cap["texts"][:2] == ["Title ✓", msg]

    def test_a_previous_modal_grab_is_handed_back(self, tk_root):
        """Tk keeps no grab stack, so a nested dialog would otherwise leave
        the shares sheet un-modal after it closed."""
        holder = tk.Toplevel(tk_root)
        holder.geometry("100x60-4000-4000")
        tk_root.update()
        holder.grab_set()
        assert tk_root.grab_current() is holder
        state = _press(tk_root, "Cancel", skip=(holder,))
        confirm(tk_root, "T", "M")
        assert state["error"] is None
        assert tk_root.grab_current() is holder
        holder.grab_release()
        holder.destroy()

    def test_no_previous_grab_leaves_the_display_ungrabbed(self, tk_root):
        assert tk_root.grab_current() is None
        _press(tk_root, "Cancel")
        confirm(tk_root, "T", "M")
        assert tk_root.grab_current() is None

    def test_a_grab_holder_that_died_meanwhile_is_not_resurrected(self, tk_root):
        holder = tk.Toplevel(tk_root)
        holder.geometry("100x60-4000-4000")
        tk_root.update()
        holder.grab_set()

        def _kill_then_cancel(win):
            holder.destroy()
            _dialog_buttons(win)[-1]._fire()

        _when_dialog(tk_root, _kill_then_cancel, skip=(holder,))
        assert confirm(tk_root, "T", "M") is False
        assert tk_root.grab_current() is None

    def test_an_unreadable_grab_state_does_not_break_the_dialog(
            self, tk_root, monkeypatch):
        monkeypatch.setattr(tk_root, "grab_current",
                            lambda: (_ for _ in ()).throw(tk.TclError("no display")))
        _press(tk_root, "Continue")
        assert confirm(tk_root, "T", "M") is True

    def test_uncentrable_dialog_still_answers(self, tk_root, monkeypatch):
        """Centring is cosmetic: a parent that cannot report its geometry
        must not stop the user answering."""
        monkeypatch.setattr(tk_root, "winfo_rootx",
                            lambda: (_ for _ in ()).throw(tk.TclError("gone")))
        _press(tk_root, "Continue")
        assert confirm(tk_root, "T", "M") is True


@requires_tkinter
class TestAlertDialog:
    """One button, no answer to give."""

    def test_alert_returns_none_and_shows_one_button(self, tk_root):
        cap = {}
        _press(tk_root, "OK", cap)
        assert alert(tk_root, "Done", "Encrypted 3 files.") is None
        assert [label for label, _bg in cap["buttons"]] == ["OK"]
        assert cap["texts"] == ["Done", "Encrypted 3 files.", "OK"]

    def test_the_ok_label_is_customisable(self, tk_root):
        cap = {}
        _press(tk_root, "Got it", cap)
        alert(tk_root, "Heads up", "FUSE is missing.", ok="Got it")
        assert [label for label, _bg in cap["buttons"]] == ["Got it"]

    def test_the_single_button_is_the_primary_accent(self, tk_root):
        cap = {}
        _press(tk_root, "OK", cap)
        alert(tk_root, "T", "M")
        assert cap["buttons"][0][1] == C["accent"]

    def test_escape_dismisses_an_alert(self, tk_root):
        _when_dialog(tk_root, lambda win: win.event_generate("<Escape>"))
        assert alert(tk_root, "T", "M") is None


# ── FlatButton ───────────────────────────────────────────────────────────────

@requires_tkinter
class TestFlatButton:
    """Flat filled button: three variants, five visual states, and a disabled
    state that neither fires nor takes focus."""

    def _btn(self, tk_root, **kw):
        calls = []
        b = FlatButton(tk_root, kw.pop("text", "Encrypt"),
                       kw.pop("command", lambda: calls.append("fired")), **kw)
        b.pack()
        tk_root.update()
        return b, calls

    def test_primary_variant_uses_the_accent_fill(self, tk_root):
        b, _ = self._btn(tk_root)
        assert b.cget("bg") == C["accent"] and b.cget("fg") == C["text"]
        assert b.cget("font") == _font(F["body_b"])
        assert int(b.cget("padx")) == SP["l"] + SP["xs"]
        assert str(b.cget("cursor")) == "hand2"

    def test_secondary_variant_sinks_into_the_surface(self, tk_root):
        b, _ = self._btn(tk_root, primary=False)
        assert b.cget("bg") == C["surface2"] and b.cget("fg") == C["text2"]

    def test_danger_variant_is_red(self, tk_root):
        b, _ = self._btn(tk_root, danger=True)
        assert b.cget("bg") == C["error_fill"]

    def test_danger_beats_primary_when_both_are_asked_for(self, tk_root):
        b, _ = self._btn(tk_root, primary=True, danger=True)
        assert b.cget("bg") == C["error_fill"]

    def test_small_variant_uses_the_small_font_and_tighter_padding(self, tk_root):
        b, _ = self._btn(tk_root, small=True)
        assert b.cget("font") == _font(F["small"])
        assert int(b.cget("padx")) == SP["m"]
        assert int(b.cget("pady")) == SP["s"] - 2

    def test_return_and_space_activate_it(self, tk_root):
        b, calls = self._btn(tk_root)
        _focus(tk_root, b)
        b.event_generate("<Return>", when="now")
        b.event_generate("<space>", when="now")
        tk_root.update()
        assert calls == ["fired", "fired"]

    def test_a_click_released_inside_fires_once(self, tk_root):
        b, calls = self._btn(tk_root)
        b.event_generate("<Button-1>", x=2, y=2)
        tk_root.update()
        assert b.cget("bg") == C["accent_press"], "press goes darker"
        b.event_generate("<ButtonRelease-1>", x=2, y=2)
        tk_root.update()
        assert calls == ["fired"]
        assert b.cget("bg") == C["accent_hover"], "pointer is still over it"

    def test_a_click_dragged_off_the_button_does_not_fire(self, tk_root):
        b, calls = self._btn(tk_root)
        b.event_generate("<Button-1>", x=2, y=2)
        b.event_generate("<ButtonRelease-1>",
                         x=b.winfo_width() + 40, y=b.winfo_height() + 40)
        tk_root.update()
        assert calls == []
        assert b.cget("bg") == C["accent"], "back to rest, not hover"

    def test_a_release_on_the_boundary_pixel_still_counts(self, tk_root):
        """The hit test is half-open: width-1 is inside, width is not."""
        b, calls = self._btn(tk_root)
        b.event_generate("<ButtonRelease-1>", x=b.winfo_width() - 1, y=0)
        tk_root.update()
        assert calls == ["fired"]
        b.event_generate("<ButtonRelease-1>", x=b.winfo_width(), y=0)
        tk_root.update()
        assert calls == ["fired"], "one past the edge is a miss"

    def test_hover_darkens_and_leaving_restores(self, tk_root):
        b, _ = self._btn(tk_root)
        b.event_generate("<Enter>")
        tk_root.update()
        assert b.cget("bg") == C["accent_hover"]
        b.event_generate("<Leave>")
        tk_root.update()
        assert b.cget("bg") == C["accent"]

    def test_focus_draws_a_ring_in_the_text_colour_on_a_filled_button(self, tk_root):
        b, _ = self._btn(tk_root)
        _focus(tk_root, b)
        assert int(b.cget("highlightthickness")) == 2
        assert b.cget("highlightbackground") == C["text"]
        other = tk.Entry(tk_root)
        other.pack()
        _focus(tk_root, other)
        assert int(b.cget("highlightthickness")) == 0

    def test_focus_ring_on_a_secondary_button_uses_the_link_colour(self, tk_root):
        b, _ = self._btn(tk_root, primary=False)
        _focus(tk_root, b)
        assert b.cget("highlightbackground") == C["accent_text"]

    def test_a_button_without_a_command_is_inert_not_broken(self, tk_root):
        b = FlatButton(tk_root, "No-op", None)
        b.pack()
        tk_root.update()
        assert b._fire() == "break", "the event is still consumed"

    def test_set_text_relabels_in_place(self, tk_root):
        b, _ = self._btn(tk_root)
        b.set_text("Encrypting…")
        tk_root.update()
        assert b.cget("text") == "Encrypting…"
        assert b.cget("bg") == C["accent"], "relabelling keeps the variant"

    def test_set_tint_selects_and_deselects_a_secondary_button(self, tk_root):
        b, _ = self._btn(tk_root, primary=False)
        b.set_tint(True)
        tk_root.update()
        assert b.cget("bg") == C["accent"] and b.cget("fg") == C["text"]
        # hovering must not undo the tint
        b.event_generate("<Enter>")
        b.event_generate("<Leave>")
        tk_root.update()
        assert b.cget("bg") == C["accent"]
        b.set_tint(False)
        tk_root.update()
        assert b.cget("bg") == C["surface2"] and b.cget("fg") == C["text2"]

    def test_tinting_a_disabled_button_only_takes_effect_on_enable(self, tk_root):
        b, _ = self._btn(tk_root, primary=False)
        b.enable(False)
        b.set_tint(True)
        tk_root.update()
        assert b.cget("bg") == C["surface"], "still reads as disabled"
        b.enable(True)
        tk_root.update()
        assert b.cget("bg") == C["accent"]

    def test_disabling_greys_it_out_and_removes_it_from_the_tab_order(self, tk_root):
        b, calls = self._btn(tk_root)
        _focus(tk_root, b)
        b.enable(False)
        tk_root.update()
        assert b.cget("fg") == C["text3"]
        assert b.cget("bg") == C["surface"]
        assert str(b.cget("cursor")) == "arrow"
        assert str(b.cget("takefocus")) == "0"
        assert int(b.cget("highlightthickness")) == 0

    def test_a_disabled_button_ignores_clicks_hover_and_keys(self, tk_root):
        b, calls = self._btn(tk_root)
        b.enable(False)
        _focus(tk_root, b)
        b.event_generate("<Enter>")
        b.event_generate("<Button-1>", x=2, y=2)
        b.event_generate("<ButtonRelease-1>", x=2, y=2)
        b.event_generate("<Return>", when="now")
        b.event_generate("<space>", when="now")
        tk_root.update()
        assert calls == []
        assert b.cget("bg") == C["surface"], "not even a hover tint"

    def test_re_enabling_restores_colour_focusability_and_the_command(self, tk_root):
        b, calls = self._btn(tk_root)
        b.enable(False)
        b.enable(True)
        tk_root.update()
        assert b.cget("bg") == C["accent"] and b.cget("fg") == C["text"]
        assert str(b.cget("takefocus")) == "1"
        b.event_generate("<ButtonRelease-1>", x=2, y=2)
        tk_root.update()
        assert calls == ["fired"]

    def test_re_enabling_under_the_pointer_shows_the_hover_colour(self, tk_root, monkeypatch):
        """Without this the button looks dead until the mouse moves again."""
        b, _ = self._btn(tk_root)
        b.enable(False)
        monkeypatch.setattr(b, "winfo_pointerxy",
                            lambda: (b.winfo_rootx() + 2, b.winfo_rooty() + 2))
        b.enable(True)
        tk_root.update()
        assert b.cget("bg") == C["accent_hover"]

    def test_re_enabling_with_the_pointer_elsewhere_stays_at_rest(self, tk_root, monkeypatch):
        b, _ = self._btn(tk_root)
        b.enable(False)
        monkeypatch.setattr(b, "winfo_pointerxy",
                            lambda: (b.winfo_rootx() + 5000, b.winfo_rooty() + 5000))
        b.enable(True)
        tk_root.update()
        assert b.cget("bg") == C["accent"]

    def test_an_unreadable_pointer_position_does_not_block_re_enabling(
            self, tk_root, monkeypatch):
        b, calls = self._btn(tk_root)
        b.enable(False)
        monkeypatch.setattr(b, "winfo_pointerxy",
                            lambda: (_ for _ in ()).throw(tk.TclError("no pointer")))
        b.enable(True)
        tk_root.update()
        assert b.cget("bg") == C["accent"]
        b.event_generate("<ButtonRelease-1>", x=2, y=2)
        tk_root.update()
        assert calls == ["fired"], "still wired up"

    def test_enable_defaults_to_true(self, tk_root):
        b, calls = self._btn(tk_root)
        b.enable(False)
        b.enable()
        tk_root.update()
        assert str(b.cget("takefocus")) == "1"

    # ── Tab order (F-009) ────────────────────────────────────────────────

    def test_a_button_nobody_enabled_is_still_in_the_tab_order(self, tk_root):
        """tk.Label defaults -takefocus to "0", which short-circuits
        ::tk::FocusOK — so before this a button reached only by Tab (Cancel,
        Close, Copy, the dialog buttons) could not be reached at all."""
        b, _ = self._btn(tk_root)          # never enable()d, as most are not
        assert str(b.cget("takefocus")) == "1"
        assert tk_root.tk.call("::tk::FocusOK", b._w) == 1

    def test_tabbing_actually_lands_on_it_and_the_key_fires_it(self, tk_root):
        entry = tk.Entry(tk_root)
        entry.pack()
        b, calls = self._btn(tk_root)
        _focus(tk_root, entry)
        nxt = tk_root.tk.call("tk_focusNext", entry._w)
        assert str(nxt) == b._w, "Tab moves from the entry onto the button"
        _focus(tk_root, b)
        b.event_generate("<Return>", when="now")
        tk_root.update()
        assert calls == ["fired"]

    def test_an_explicit_takefocus_still_wins(self, tk_root):
        b, _ = self._btn(tk_root, takefocus=0)
        assert str(b.cget("takefocus")) == "0"


# ── SegmentedControl ─────────────────────────────────────────────────────────

@requires_tkinter
class TestSegmentedControl:
    """Pill toggle bound to a Tk variable: the variable is the single source
    of truth, in both directions, and freezes with the rest of the form."""

    def _control(self, tk_root, value="pw", options=None):
        var = _traced_var(tk_root, value)
        sc = SegmentedControl(
            tk_root, options or [("pw", "Password"), ("sh", "Shares")], var)
        sc.pack()
        tk_root.update()
        return sc, var

    def _bgs(self, sc):
        return {val: lbl.cget("bg") for val, lbl in sc._labels.items()}

    def test_the_selected_option_is_filled_and_the_others_are_not(self, tk_root):
        sc, _ = self._control(tk_root)
        assert self._bgs(sc) == {"pw": C["accent"], "sh": C["surface"]}
        assert sc._labels["pw"].cget("fg") == C["text"]
        assert sc._labels["sh"].cget("fg") == C["text3"]

    def test_every_option_is_rendered_with_its_label(self, tk_root):
        sc, _ = self._control(tk_root)
        assert _texts(sc) == ["Password", "Shares"]

    def test_clicking_an_option_sets_the_variable_and_repaints(self, tk_root):
        sc, var = self._control(tk_root)
        sc._labels["sh"].event_generate("<Button-1>", x=2, y=2)
        tk_root.update()
        assert var.get() == "sh"
        assert self._bgs(sc) == {"pw": C["surface"], "sh": C["accent"]}

    def test_setting_the_variable_repaints_without_a_click(self, tk_root):
        sc, var = self._control(tk_root)
        var.set("sh")
        tk_root.update()
        assert self._bgs(sc)["sh"] == C["accent"]

    def test_arrow_keys_walk_the_options_and_wrap(self, tk_root):
        sc, var = self._control(
            tk_root, options=[("a", "A"), ("b", "B"), ("c", "C")], value="a")
        _focus(tk_root, sc)
        seen = []
        for _ in range(4):
            sc.event_generate("<Right>", when="now")
            tk_root.update()
            seen.append(var.get())
        assert seen == ["b", "c", "a", "b"]
        sc.event_generate("<Left>", when="now")
        tk_root.update()
        assert var.get() == "a"

    def test_stepping_left_from_the_first_option_wraps_to_the_last(self, tk_root):
        sc, var = self._control(
            tk_root, options=[("a", "A"), ("b", "B"), ("c", "C")], value="a")
        sc._step(-1)
        assert var.get() == "c"

    def test_a_single_option_control_stays_put(self, tk_root):
        sc, var = self._control(tk_root, options=[("only", "Only")], value="only")
        sc._step(1)
        sc._step(-1)
        assert var.get() == "only"
        assert self._bgs(sc) == {"only": C["accent"]}

    def test_a_control_with_no_options_has_nothing_to_step_through(self, tk_root):
        """Zero-element edge, and the BAD path that follows from it: the step
        wraps modulo the option count, so there is nothing sane to wrap into.
        It raises rather than quietly leaving the variable somewhere odd."""
        var = _traced_var(tk_root, "x")
        sc = SegmentedControl(tk_root, [], var)
        sc.pack()
        tk_root.update()
        assert _texts(sc) == [] and sc._labels == {}
        with pytest.raises(ZeroDivisionError):
            sc._step(1)
        assert var.get() == "x", "the variable was not touched on the way out"

    def test_a_variable_holding_an_unknown_value_steps_from_the_start(self, tk_root):
        """Nothing is highlighted, so the first arrow press has to land
        somewhere sensible rather than raise."""
        sc, var = self._control(tk_root)
        var.set("bogus")
        tk_root.update()
        assert self._bgs(sc) == {"pw": C["surface"], "sh": C["surface"]}
        sc._step(1)
        assert var.get() == "sh"

    def test_focus_thickens_the_ring_and_blur_restores_it(self, tk_root):
        sc, _ = self._control(tk_root)
        _focus(tk_root, sc)
        assert int(sc.cget("highlightthickness")) == 2
        assert sc.cget("highlightbackground") == C["accent_text"]
        other = tk.Entry(tk_root)
        other.pack()
        _focus(tk_root, other)
        assert int(sc.cget("highlightthickness")) == 1
        assert sc.cget("highlightbackground") == C["border"]

    def test_return_still_reaches_the_parent_window(self, tk_root):
        """DEFECT, documented rather than asserted-as-wanted: the control
        binds ``<Return>`` to ``lambda e: None`` with the comment "absorb so
        form doesn't submit on focus", but a Tk binding only stops
        propagation when it returns "break".  Plain Return therefore still
        reaches the toplevel.  Harmless today (both wizards bind ⌘/Ctrl-Return
        rather than plain Return), so this pins current behaviour; flip the
        expectation when the binding is fixed."""
        submitted = []
        tk_root.bind("<Return>", lambda e: submitted.append("submit"))
        sc, _ = self._control(tk_root)
        _focus(tk_root, sc)
        sc.event_generate("<Return>", when="now")
        tk_root.update()
        assert submitted == ["submit"]

    def test_return_does_not_change_the_selection(self, tk_root):
        """Whatever else Return does, it must not switch mode."""
        sc, var = self._control(tk_root)
        _focus(tk_root, sc)
        sc.event_generate("<Return>", when="now")
        tk_root.update()
        assert var.get() == "pw"

    def test_disabling_freezes_clicks_arrows_and_the_tab_order(self, tk_root):
        sc, var = self._control(tk_root)
        sc.set_enabled(False)
        _focus(tk_root, sc)
        sc._labels["sh"].event_generate("<Button-1>", x=2, y=2)
        sc.event_generate("<Right>", when="now")
        tk_root.update()
        assert var.get() == "pw"
        assert str(sc.cget("takefocus")) == "0"
        assert all(lbl.cget("fg") == C["text3"] for lbl in sc._labels.values())
        assert all(str(lbl.cget("cursor")) == "arrow" for lbl in sc._labels.values())

    def test_re_enabling_restores_clicks_arrows_and_the_highlight(self, tk_root):
        sc, var = self._control(tk_root)
        sc.set_enabled(False)
        sc.set_enabled(True)
        tk_root.update()
        assert str(sc.cget("takefocus")) == "1"
        assert all(str(lbl.cget("cursor")) == "hand2" for lbl in sc._labels.values())
        assert self._bgs(sc)["pw"] == C["accent"], "the selection is repainted"
        sc._labels["sh"].event_generate("<Button-1>", x=2, y=2)
        tk_root.update()
        assert var.get() == "sh"
        _focus(tk_root, sc)
        sc.event_generate("<Right>", when="now")
        tk_root.update()
        assert var.get() == "pw"


# ── StagedProgressBar ────────────────────────────────────────────────────────

@requires_tkinter
class TestStagedProgressBar:
    """Weighted stages, an ETA that is re-armed exactly once per tick, and a
    visual state that never survives into the next run."""

    STAGES = [("Deriving key", 3), ("Encrypting", 6), ("Writing", 1)]

    def _bar(self, tk_root, stages=None):
        bar = StagedProgressBar(tk_root, stages or self.STAGES)
        bar.pack(fill="x", padx=10)
        tk_root.update()
        return bar

    def _labels(self, bar):
        return (bar._stage_lbl.cget("text"), bar._pct_lbl.cget("text"),
                bar._time_lbl.cget("text"))

    def test_stage_offsets_are_cumulative_and_normalised(self, tk_root):
        bar = self._bar(tk_root)
        assert bar._stage_pcts == [0.0, 0.3, 0.9]

    def test_equal_weights_split_evenly(self, tk_root):
        bar = self._bar(tk_root, [("a", 1), ("b", 1), ("c", 1), ("d", 1)])
        assert bar._stage_pcts == [0.0, 0.25, 0.5, 0.75]

    def test_a_single_stage_starts_at_zero(self, tk_root):
        bar = self._bar(tk_root, [("only", 1)])
        assert bar._stage_pcts == [0.0]
        assert len(bar._dot_cvs) == 1 and bar._connector_cvs == []

    def test_one_dot_per_stage_with_connectors_between(self, tk_root):
        bar = self._bar(tk_root)
        assert len(bar._dot_cvs) == 3 and len(bar._connector_cvs) == 2

    def test_no_stages_at_all_still_starts(self, tk_root):
        """Zero-element edge: no dots, no connectors, no offsets — and the
        header still paints, because the caller may only be showing "busy"."""
        bar = StagedProgressBar(tk_root, [])   # not self._bar: [] or STAGES
        bar.pack(fill="x", padx=10)
        tk_root.update()
        assert bar._stage_pcts == []
        assert bar._dot_cvs == [] and bar._connector_cvs == []
        bar.start()
        tk_root.update()
        assert self._labels(bar) == ("Starting…", "0%", "calculating...")
        bar.stop()

    def test_stages_that_all_weigh_nothing_are_rejected_at_construction(
            self, tk_root):
        """BAD path: each offset is that stage's share of the total weight, so
        a zero total has no answer.  It raises where the stage list is written
        rather than pinning every stage to 0% for the whole run."""
        before = len(tk_root.winfo_children())
        with pytest.raises(ZeroDivisionError):
            StagedProgressBar(tk_root, [("a", 0), ("b", 0)])
        # The Frame exists (tk.Frame.__init__ ran first) but nothing was ever
        # packed or drawn, so no half-built bar reaches the screen.
        leftovers = tk_root.winfo_children()[before:]
        assert all(not w.winfo_ismapped() for w in leftovers)
        assert all(not w.winfo_children() for w in leftovers)

    def test_start_paints_the_starting_state(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        tk_root.update()
        # start() runs one ETA tick synchronously, so the time label is
        # already in its "no estimate yet" state.
        assert self._labels(bar) == ("Starting…", "0%", "calculating...")
        assert bar._current == -1 and bar._pct == 0.0 and bar._running is True
        assert bar._stage_lbl.cget("fg") == C["text"]
        bar.stop()

    def test_advance_names_the_stage_and_moves_to_its_offset(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(1)
        tk_root.update()
        assert bar._stage_lbl.cget("text") == "Encrypting"
        assert bar._pct == pytest.approx(0.3)
        bar.stop()

    def test_a_percentage_in_the_message_interpolates_inside_the_stage(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(1, "Encrypting payload... 50%")
        assert bar._pct == pytest.approx(0.3 + 0.5 * (0.9 - 0.3))
        bar.advance(1, "Encrypting payload... 0%")
        assert bar._pct == pytest.approx(0.3)
        bar.advance(1, "Encrypting payload... 100%")
        assert bar._pct == pytest.approx(0.9)
        bar.stop()

    def test_a_percentage_over_one_hundred_is_clamped(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(0, "Deriving key 250%")
        assert bar._pct == pytest.approx(0.3), "cannot spill into the next stage"
        bar.stop()

    def test_the_last_stage_interpolates_up_to_one(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(2, "Writing 50%")
        assert bar._pct == pytest.approx(0.9 + 0.5 * 0.1)
        bar.stop()

    def test_advancing_past_the_last_stage_pins_at_full(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(len(self.STAGES))
        tk_root.update()
        assert bar._pct == 1.0
        assert bar._stage_lbl.cget("text") == ""
        bar.stop()

    def test_a_custom_message_overrides_the_stage_name(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(0, "Deriving key (Argon2id)")
        tk_root.update()
        # the pulse owns the trailing dots, so the message shows with one
        assert bar._stage_lbl.cget("text") == "Deriving key (Argon2id)."
        bar.stop()

    def test_re_advancing_the_same_stage_keeps_the_stage_clock(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(1, "Encrypting 10%")
        first = bar._stage_t
        bar.advance(1, "Encrypting 20%")
        assert bar._stage_t == first
        bar.advance(2, "Writing")
        assert bar._stage_t > first, "a new stage restarts the stage clock"
        bar.stop()

    def test_complete_paints_everything_green_and_reports_the_elapsed_time(
            self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar._start_t = _time.time() - 2.0
        bar.complete()
        tk_root.update()
        stage, pct, elapsed = self._labels(bar)
        assert (stage, pct) == ("Complete", "100%")
        assert elapsed.endswith("s") and float(elapsed[:-1]) >= 2.0
        assert bar._stage_lbl.cget("fg") == C["success"]
        assert bar._pct_lbl.cget("fg") == C["success"]
        assert bar._time_lbl.cget("fg") == C["success"]
        assert bar._pct == 1.0 and bar._running is False

    def test_complete_without_start_reports_zero(self, tk_root):
        bar = self._bar(tk_root)
        bar.complete()
        assert self._labels(bar)[2] == "0.0s"

    def test_a_second_run_does_not_inherit_the_completed_state(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(2)
        bar.complete()
        tk_root.update()
        bar.start()
        tk_root.update()
        assert self._labels(bar) == ("Starting…", "0%", "calculating...")
        assert bar._pct_lbl.cget("fg") == C["text2"]
        assert bar._current == -1
        assert _canvas_colours(bar._dot_cvs[0], "oval") == [C["surface3"]]
        bar.stop()

    def test_stop_halts_the_loops_without_claiming_success(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(0, "Deriving key")
        bar.stop()
        assert bar._running is False
        assert bar._time_job is None and bar._pulse_job is None
        assert bar._stage_lbl.cget("text") != "Complete"

    def test_destroy_leaves_no_pending_timers(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(0, "Deriving key")
        assert tk_root.tk.call("after", "info"), "the bar armed some timers"
        bar.destroy()
        tk_root.update()
        assert not tk_root.tk.call("after", "info")

    def test_a_stale_timer_id_does_not_break_cancellation(self, tk_root):
        """after_cancel throws on an id Tk has already fired."""
        bar = self._bar(tk_root)
        bar._time_job = "after#not-a-real-id"
        bar._pulse_job = "after#nor-this-one"
        bar._cancel_jobs()
        assert bar._time_job is None and bar._pulse_job is None

    def test_the_filled_width_tracks_the_percentage(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        w = bar._bar_w
        assert w > 2, "the canvas was laid out"
        bar.advance(1)          # 30%
        tk_root.update()
        items = bar._bar_cv.find_all()
        assert len(items) == 2, "background plus fill"
        assert bar._bar_cv.itemcget(items[1], "fill") == C["accent"]
        fill_w = bar._bar_cv.coords(items[1])[2]
        assert fill_w == pytest.approx(int(w * 0.3), abs=1)
        bar.stop()

    def test_nothing_is_filled_at_zero_percent(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        tk_root.update()
        assert len(bar._bar_cv.find_all()) == 1, "background only"
        bar.stop()

    def test_completion_turns_the_fill_green(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.complete()
        tk_root.update()
        items = bar._bar_cv.find_all()
        assert bar._bar_cv.itemcget(items[1], "fill") == C["success"]

    def test_an_unlaid_out_bar_draws_nothing(self, tk_root):
        """_draw_bar runs on every progress message and must not pump the
        event loop to discover its own width."""
        bar = StagedProgressBar(tk_root, self.STAGES)   # never packed
        bar._pct = 0.5
        bar._draw_bar()
        assert bar._bar_w == 0 and bar._bar_cv.find_all() == ()
        # …and the guard is about the width alone, not a refusal to draw:
        # 1 is still too narrow, 2 is the first width that paints.
        bar._bar_w = 1
        bar._draw_bar()
        assert bar._bar_cv.find_all() == ()
        bar._bar_w = 2
        bar._draw_bar()
        assert len(bar._bar_cv.find_all()) == 2, "background plus fill"
        bar._bar_w = 200
        bar._draw_bar()
        assert bar._bar_cv.coords(bar._bar_cv.find_all()[1])[2] == 100

    def test_a_resize_repaints_at_the_new_width(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(1)
        tk_root.update()
        narrow = bar._bar_cv.coords(bar._bar_cv.find_all()[1])[2]
        bar.pack_configure(padx=120)
        tk_root.update()
        wide = bar._bar_cv.coords(bar._bar_cv.find_all()[1])[2]
        assert wide < narrow, "the fill shrank with the canvas"
        bar.stop()

    def test_a_resize_after_completion_keeps_the_green_fill(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.complete()
        bar.pack_configure(padx=60)
        tk_root.update()
        items = bar._bar_cv.find_all()
        assert bar._bar_cv.itemcget(items[1], "fill") == C["success"]

    def test_dots_show_done_current_and_pending(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(1)
        tk_root.update()
        assert [_canvas_colours(cv, "oval")[0] for cv in bar._dot_cvs] == [
            C["success"], C["accent"], C["surface3"]]
        assert [cv.cget("bg") for cv in bar._connector_cvs] == [
            C["success"], C["border"]]
        bar.stop()

    def test_completion_turns_every_dot_and_connector_green(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.complete()
        tk_root.update()
        assert {_canvas_colours(cv, "oval")[0] for cv in bar._dot_cvs} == {C["success"]}
        assert {cv.cget("bg") for cv in bar._connector_cvs} == {C["success"]}

    def test_the_eta_loop_is_armed_once_and_re_arms_itself(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        first = bar._time_job
        assert first is not None
        for i in range(50):
            bar.advance(1, f"Encrypting {i}%")
        assert bar._time_job == first, "advance() must never arm a second loop"
        _pump_until(tk_root, lambda: bar._time_job != first, timeout=2.0)
        assert bar._time_job not in (None, first), "the tick re-armed itself"
        bar.stop()

    def test_the_eta_loop_stops_itself_once_stopped(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar._running = False
        bar._update_time()
        assert bar._time_job is None

    def test_the_eta_loop_does_not_re_arm_at_one_hundred_percent(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar._pct = 1.0
        bar._update_time()
        assert bar._time_job is None

    def test_early_on_the_time_label_says_it_is_calculating(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar._pct = 0.005
        bar._refresh_time_labels()
        assert self._labels(bar)[1:] == ("0%", "calculating...")
        bar.stop()

    def test_a_long_slow_stage_estimates_the_time_left(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        now = _time.time()
        bar._current = 1
        bar._start_t = now - 10.0
        bar._stage_t = now - 5.0          # 5 s spent on 30% of the job so far
        bar._pct = 0.6
        bar._refresh_time_labels()
        pct, remaining = self._labels(bar)[1:]
        assert pct == "60%"
        # 30 points in 5 s → 6 points/s → the last 40 points take ~7 s
        assert remaining == "~7s left"
        bar.stop()

    def test_the_final_moments_say_almost_done(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        now = _time.time()
        bar._current = 1
        bar._start_t = now - 10.0
        bar._stage_t = now - 5.0
        bar._pct = 0.95
        bar._refresh_time_labels()
        assert self._labels(bar)[1:] == ("95%", "almost done...")
        bar.stop()

    def test_before_a_stage_has_a_rate_the_whole_job_is_extrapolated(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        now = _time.time()
        bar._current = 0
        bar._start_t = now - 4.0
        bar._stage_t = now - 0.1          # too little stage history to trust
        bar._pct = 0.2
        bar._refresh_time_labels()
        # 20% in 4 s → 20 s total → ~16 s left
        assert self._labels(bar)[1:] == ("20%", "~16s left")
        bar.stop()

    def test_time_labels_are_left_alone_when_the_bar_is_not_running(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.complete()
        before = self._labels(bar)
        bar._refresh_time_labels()
        assert self._labels(bar) == before

    def test_the_stage_label_pulses_while_there_is_no_sub_progress(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(0, "Deriving key")
        tk_root.update()
        assert bar._stage_lbl.cget("text") == "Deriving key."
        bar._pulse_tick(1)
        assert bar._stage_lbl.cget("text") == "Deriving key.."
        bar._pulse_tick(2)
        assert bar._stage_lbl.cget("text") == "Deriving key..."
        bar._pulse_tick(3)
        assert bar._stage_lbl.cget("text") == "Deriving key.", "the cycle wraps"
        bar.stop()

    def test_a_second_message_in_the_same_stage_re_arms_one_pulse(self, tk_root):
        """Each advance() restarts the pulse; without cancelling the previous
        one the label would be animated by several timers at once."""
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(0, "Deriving key")
        first = bar._pulse_job
        assert first is not None
        bar.advance(0, "Deriving key")
        assert bar._pulse_job not in (None, first)
        assert len(tk_root.tk.call("after", "info")) == 2, "one ETA, one pulse"
        bar.stop()

    def test_the_pulse_does_not_pile_up_ellipses(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(0, "Deriving key…")
        bar._pulse_tick(1)
        assert bar._stage_lbl.cget("text") == "Deriving key.."
        bar.stop()

    def test_real_progress_ends_the_pulse_and_restores_the_label(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(1, "Encrypting 40%")
        tk_root.update()
        assert bar._stage_lbl.cget("text") == "Encrypting 40%"
        assert bar._pulse_job is None, "no pulse while there is real progress"
        bar.stop()

    def test_stopping_ends_the_pulse_loop(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(0, "Deriving key")
        bar.stop()
        bar._pulse_tick(0)
        assert bar._pulse_job is None, "a stopped pulse never re-arms"

    def test_a_destroyed_label_does_not_kill_the_pulse_callback(self, tk_root):
        bar = self._bar(tk_root)
        bar.start()
        bar.advance(0, "Deriving key")
        bar._stage_lbl.destroy()
        bar._pulse_tick(1)               # contract: the timer callback survives
        assert bar._pulse_job is not None
        bar.stop()


# ── PasswordStrengthBar ──────────────────────────────────────────────────────

@requires_tkinter
class TestPasswordStrengthBar:
    """Live strength meter.  Scoring is off the main thread, results for
    superseded text are dropped, and the submit path never blocks the window
    on a fresh zxcvbn run."""

    def _bar(self, tk_root, value=""):
        return _new_strength_bar(tk_root, value)

    def _settled(self, tk_root, bar, pw):
        return _pump_until(tk_root, lambda: bar._last[0] == pw, timeout=8.0)

    def test_a_fresh_bar_shows_nothing(self, tk_root):
        bar, _ = self._bar(tk_root)
        assert bar._lbl.cget("text") == ""
        assert bar._tip.cget("text") == " "
        assert bar._last == ("", 0, "", "")

    def test_typing_a_weak_password_names_it_and_offers_advice(self, tk_root):
        bar, var = self._bar(tk_root)
        var.set("password")
        assert self._settled(tk_root, bar, "password")
        pw, score, label, tip = bar._last
        assert score == 0 and label == "Very Weak"
        assert bar._lbl.cget("text") == "Very Weak"
        assert bar._lbl.cget("fg") == C["error"]
        assert tip and bar._tip.cget("text") == tip

    def test_typing_a_strong_passphrase_scores_at_the_top(self, tk_root):
        bar, var = self._bar(tk_root)
        pw = "Tr0ub4dor-&-c0rrect-horse-batteryStaple!"
        var.set(pw)
        assert self._settled(tk_root, bar, pw)
        assert bar._last[1] == 4
        assert bar._lbl.cget("text") == "Strong"
        assert bar._lbl.cget("fg") == C["success"]

    def test_clearing_the_field_clears_the_meter(self, tk_root):
        bar, var = self._bar(tk_root)
        var.set("password")
        assert self._settled(tk_root, bar, "password")
        var.set("")
        assert self._settled(tk_root, bar, "")
        assert bar._last == ("", 0, "", "")
        assert bar._lbl.cget("text") == "" and bar._tip.cget("text") == ""
        assert bar._inflight is None, "nothing left to wait for"
        assert bar._lbl.cget("fg") == C["surface3"]

    def test_a_burst_of_keystrokes_is_scored_once(self, tk_root):
        """The debounce exists because zxcvbn costs hundreds of ms on a long
        passphrase; one score per pause, not one per keystroke."""
        bar, var = self._bar(tk_root)
        for pw in ("c", "co", "cor", "corr", "corre", "correct"):
            var.set(pw)
        assert self._settled(tk_root, bar, "correct")
        assert bar._seq == 1, f"{bar._seq} scoring passes for one burst"

    def test_the_bar_fill_grows_with_the_score(self, tk_root):
        bar, var = self._bar(tk_root)
        var.set("password")
        assert self._settled(tk_root, bar, "password")
        assert len(bar._bar_cv.find_all()) == 1, "score 0 fills nothing"
        var.set("Tr0ub4dor-&-c0rrect-horse-batteryStaple!")
        assert self._settled(tk_root, bar, "Tr0ub4dor-&-c0rrect-horse-batteryStaple!")
        items = bar._bar_cv.find_all()
        assert len(items) == 2
        assert bar._bar_cv.itemcget(items[1], "fill") == C["success"]
        assert bar._bar_cv.coords(items[1])[2] == pytest.approx(bar._bar_w, abs=1)

    def test_a_resize_redraws_at_the_new_width(self, tk_root):
        bar, var = self._bar(tk_root)
        var.set("Tr0ub4dor-&-c0rrect-horse-batteryStaple!")
        assert self._settled(tk_root, bar, "Tr0ub4dor-&-c0rrect-horse-batteryStaple!")
        wide = bar._bar_cv.coords(bar._bar_cv.find_all()[1])[2]
        bar.pack_configure(padx=140)
        tk_root.update()
        narrow = bar._bar_cv.coords(bar._bar_cv.find_all()[1])[2]
        assert narrow < wide

    def test_an_unlaid_out_bar_draws_nothing(self, tk_root):
        var = _traced_var(tk_root)
        bar = PasswordStrengthBar(tk_root, var)      # never packed
        _LIVE_BARS.append(bar)
        bar._draw(4, "whatever")
        assert bar._bar_w == 0 and bar._bar_cv.find_all() == ()
        # …the guard is the width, not the drawing: hand it the width a
        # <Configure> would have brought and a full-score bar fills the track.
        bar._bar_w = 200
        bar._draw(4, "whatever")
        items = bar._bar_cv.find_all()
        assert len(items) == 2
        assert bar._bar_cv.coords(items[1])[2] == 200
        assert bar._bar_cv.itemcget(items[1], "fill") == C["success"]

    def test_a_stale_worker_result_is_dropped(self, tk_root):
        bar, _ = self._bar(tk_root)
        bar._seq = 7
        bar._apply(6, "old text", 4, "Strong", "stale tip")
        assert bar._last == ("", 0, "", "")
        assert bar._lbl.cget("text") == ""
        bar._apply(7, "new text", 3, "Good", "fresh tip")
        assert bar._last == ("new text", 3, "Good", "fresh tip")
        assert bar._lbl.cget("text") == "Good"
        assert bar._tip.cget("text") == "fresh tip"

    @pytest.mark.parametrize("score,colour", [
        (0, "error"), (1, "error"), (2, "warning"), (3, "success"), (4, "success")])
    def test_the_colour_ramp_is_quality_only(self, score, colour):
        assert PasswordStrengthBar._colour(score, "pw") == C[colour]

    def test_an_empty_password_is_greyed_out_whatever_the_score(self):
        assert PasswordStrengthBar._colour(4, "") == C["surface3"]

    # ── the scorer itself ────────────────────────────────────────────────

    def test_score_of_an_empty_password_is_zero_with_no_label(self, tk_root):
        bar, _ = self._bar(tk_root)
        assert bar._score("") == (0, "", "")

    def test_zxcvbn_scores_the_whole_ramp_and_passes_its_advice_through(
            self, tk_root):
        """Every rung of the 0-4 scale with the label the scale defines, the
        warning zxcvbn actually gives at the weak end, and no advice invented
        at the strong end.  One bar rather than a parametrize: a Tk root costs
        seconds to build, and _score does not depend on widget state."""
        bar, _ = self._bar(tk_root)
        assert bar._score("password") == (
            0, "Very Weak", "This is a top-10 common password.")
        assert bar._score("hunter2") == (
            1, "Weak", "This is a very common password.")
        assert bar._score("mocha42Q") == (
            2, "Fair", "Add another word or two. Uncommon words are better.")
        assert bar._score("aztec-cup") == (3, "Good", "")
        assert bar._score("Tr0ub4dor&3") == (4, "Strong", "")

    def test_only_the_first_suggestion_is_shown_and_the_warning_wins(self, tk_root):
        """The tip line is one line high, so at most one string comes out of
        the feedback block — the warning when there is one, otherwise the
        first suggestion."""
        bar, _ = self._bar(tk_root)
        raw = shared._zxcvbn_fn("qwerty123")
        assert raw["feedback"]["warning"] and len(raw["feedback"]["suggestions"]) >= 1
        assert bar._score("qwerty123")[2] == raw["feedback"]["warning"]
        # "mocha42Q" has no warning, so the first suggestion is used instead
        raw2 = shared._zxcvbn_fn("mocha42Q")
        assert not raw2["feedback"]["warning"]
        assert bar._score("mocha42Q")[2] == raw2["feedback"]["suggestions"][0]

    def test_a_password_over_the_zxcvbn_cap_is_scored_on_its_prefix(self, tk_root):
        """zxcvbn hard-refuses input longer than 72 characters, so the bar
        has to truncate rather than let a long passphrase raise."""
        bar, _ = self._bar(tk_root)
        long = "Zq7!" * 50            # 200 characters
        with pytest.raises(ValueError, match="max length of 72"):
            shared._zxcvbn_fn(long)
        assert bar._score(long) == bar._score(long[:72])
        assert bar._score(long)[1] in PasswordStrengthBar._LABELS

    def test_a_unicode_password_is_scored_without_blowing_up(self, tk_root):
        bar, var = self._bar(tk_root)
        pw = "ünïcode-паssword-✓-日本語"
        var.set(pw)
        assert self._settled(tk_root, bar, pw)
        # Non-ASCII is outside every zxcvbn dictionary, so this scores at the
        # top of the scale — the point being it is graded, not merely survived.
        assert bar._last == (pw, 4, "Strong", "")
        assert bar._lbl.cget("text") == "Strong"
        assert bar._lbl.cget("fg") == C["success"]

    @pytest.mark.parametrize("pw,score,label", [
        ("abcde", 1, "Weak"),          # 5 × log2(26) = 23.5 bits, under 28
        ("abcdef", 2, "Fair"),         # 6 × log2(26) = 28.2 bits, over 28
        ("abcdefgh", 3, "Good"),       # 37.6 bits
        ("abcdefghijklm", 4, "Strong"),  # 61.1 bits
        ("12345678", 1, "Weak"),       # digits only: pool 10 → 26.6 bits
        ("AB1!x", 2, "Fair"),          # all four classes: pool 94 → 32.8 bits
        ("   ", 1, "Weak"),            # symbols only: pool 32 → 15 bits
    ])
    def test_the_fallback_estimator_bands(self, tk_root, monkeypatch, pw, score, label):
        """Without the optional zxcvbn extra the bar still has to say
        something honest, from character-pool entropy."""
        monkeypatch.setattr(shared, "_zxcvbn_fn", None)
        bar, _ = self._bar(tk_root)
        assert bar._score(pw) == (score, label, "")

    def test_the_fallback_estimator_still_zeroes_an_empty_password(
            self, tk_root, monkeypatch):
        monkeypatch.setattr(shared, "_zxcvbn_fn", None)
        bar, _ = self._bar(tk_root)
        assert bar._score("") == (0, "", "")

    def test_the_fallback_estimator_drives_the_widget(self, tk_root, monkeypatch):
        monkeypatch.setattr(shared, "_zxcvbn_fn", None)
        bar, var = self._bar(tk_root)
        var.set("abcdefghijklm")
        assert self._settled(tk_root, bar, "abcdefghijklm")
        assert bar._lbl.cget("text") == "Strong"
        assert bar._tip.cget("text") == "", "the fallback has no advice to give"

    # ── score_for(), the submit path ─────────────────────────────────────

    def test_score_for_reuses_the_score_already_on_screen(self, tk_root, monkeypatch):
        # A password that scores 4, not 0 — a cached 4 cannot be confused with
        # the "nothing scored yet" default that a broken cache would return.
        bar, var = self._bar(tk_root)
        var.set("Tr0ub4dor&3")
        assert self._settled(tk_root, bar, "Tr0ub4dor&3")
        monkeypatch.setattr(bar, "_score", lambda pw: pytest.fail(
            "scored synchronously on the main thread"))
        assert bar.score_for("Tr0ub4dor&3") == 4

    def test_score_for_returns_the_last_score_for_unseen_text(self, tk_root, monkeypatch):
        bar, var = self._bar(tk_root)
        var.set("Tr0ub4dor-&-c0rrect-horse-batteryStaple!")
        assert self._settled(tk_root, bar, "Tr0ub4dor-&-c0rrect-horse-batteryStaple!")
        monkeypatch.setattr(bar, "_score", lambda pw: pytest.fail(
            "scored synchronously on the main thread"))
        # nothing is in flight for this text, so the previous score stands
        assert bar.score_for("something else entirely") == 4

    def test_score_for_inside_the_debounce_window_kicks_the_worker(self, tk_root):
        """A fast typist who hits Return 20 ms after the last keystroke must
        still be graded on what they typed."""
        bar, var = self._bar(tk_root)
        var.set("Tr0ub4dor&3")
        assert bar._refresh_job is not None, "still debouncing"
        # 4, not the 0 a bar that never scored anything would report: the
        # worker really was kicked and really was waited for.
        assert bar.score_for("Tr0ub4dor&3") == 4
        assert bar._last == ("Tr0ub4dor&3", 4, "Strong", "")
        assert bar._refresh_job is None, "the pending debounce was consumed"

    def test_score_for_gives_up_on_a_worker_that_is_too_slow(self, tk_root, monkeypatch):
        bar, var = self._bar(tk_root)
        var.set("Tr0ub4dor&3")
        assert self._settled(tk_root, bar, "Tr0ub4dor&3")
        monkeypatch.setattr(bar, "_SUBMIT_WAIT_S", 0.05)
        never = threading.Event()
        bar._inflight = ("slow text", never, {"seq": bar._seq})
        started = _time.monotonic()
        # The last APPLIED score (4), not a placeholder 0 and not a blocking
        # zxcvbn run on the main thread.
        assert bar.score_for("slow text") == 4, "falls back to the last score"
        assert _time.monotonic() - started < 2.0, "it waited briefly, not forever"
        assert bar._last == ("Tr0ub4dor&3", 4, "Strong", ""), \
            "nothing was applied for the text that never came back"

    def test_score_for_of_the_empty_string_is_zero(self, tk_root):
        bar, _ = self._bar(tk_root)
        assert bar.score_for("") == 0

    # ── the worker thread ────────────────────────────────────────────────

    def test_the_worker_scores_only_the_newest_queued_text(self, tk_root):
        """A burst of pauses used to spawn one zxcvbn run each."""
        bar, _ = self._bar(tk_root)
        items = []
        for i, pw in enumerate(["a", "ab", "correct horse battery"], start=1):
            ev, holder = threading.Event(), {"seq": i}
            bar._queue.put((i, pw, ev, holder))
            items.append((ev, holder))
        _spawn_worker(bar)
        assert items[-1][0].wait(5), "the newest request was scored"
        assert "res" not in items[0][1] and "res" not in items[1][1]
        assert not items[0][0].is_set() and not items[1][0].is_set(), \
            "the superseded waiters are never released either"
        assert items[-1][1]["res"] == (4, "Strong", ""), \
            "and it is the newest text that was scored, not the oldest"

    def test_a_scorer_that_blows_up_yields_a_neutral_result(self, tk_root, monkeypatch):
        bar, _ = self._bar(tk_root)
        monkeypatch.setattr(bar, "_score",
                            lambda pw: (_ for _ in ()).throw(RuntimeError("boom")))
        ev, holder = threading.Event(), {"seq": 1}
        bar._queue.put((1, "anything", ev, holder))
        _spawn_worker(bar)
        assert ev.wait(5)
        assert holder["res"] == (0, "", ""), "a crash must not wedge the submit path"

    def test_an_idle_worker_exits_instead_of_parking_forever(self, tk_root, monkeypatch):
        """A closed window must not leave a thread behind."""
        bar, _ = self._bar(tk_root)
        monkeypatch.setattr(bar._queue, "get",
                            lambda timeout=None: (_ for _ in ()).throw(queue.Empty))
        t = threading.Thread(target=bar._worker_loop)
        t.start()
        t.join(3)
        assert not t.is_alive()

    def test_the_worker_hands_its_result_back_on_the_main_thread(self, tk_root):
        bar, var = self._bar(tk_root)
        var.set("password")
        assert self._settled(tk_root, bar, "password")
        assert bar._thread is not None and bar._thread.daemon
        assert bar._lbl.cget("text") == "Very Weak", "the label was updated for us"


# ── FileCard ─────────────────────────────────────────────────────────────────

@requires_tkinter
class TestFileCard:
    """The drop-zone / picker shared by the encryptor and the decryptor: it
    owns its own selected/unselected presentation and never promises drag &
    drop it cannot deliver."""

    def _card(self, tk_root, **kw):
        picked, foldered = [], []
        fc = FileCard(tk_root, picked.append,
                      on_folder=kw.pop("on_folder", None), **kw)
        fc.pack(fill="x")
        tk_root.update()
        return fc, picked, foldered

    def _dialog(self, monkeypatch, *, file="", folder=""):
        """Swap the modal OS file dialog for a recorder."""
        from tkinter import filedialog
        seen = {}

        def _open(**kw):
            seen["open"] = kw
            return file

        def _dir(**kw):
            seen["dir"] = kw
            return folder

        monkeypatch.setattr(filedialog, "askopenfilename", _open)
        monkeypatch.setattr(filedialog, "askdirectory", _dir)
        return seen

    def _widgets(self, fc):
        return [fc, fc._icon, fc._line1, fc._line2]

    def test_the_unselected_card_invites_a_choice(self, tk_root):
        fc, _, _ = self._card(tk_root, prompt="Select a .qcx file",
                              sub="Click anywhere in this box")
        assert _texts(fc) == ["+", "Select a .qcx file", "Click anywhere in this box"]
        assert fc.cget("bg") == C["surface"]
        assert str(fc.cget("highlightbackground")) == C["border"]
        assert str(fc.cget("cursor")) == "hand2"
        assert str(fc.cget("takefocus")) == "1"

    def test_clicking_opens_the_picker_and_reports_the_choice(
            self, tk_root, tmp_path, monkeypatch):
        f = tmp_path / "vault.qcx"
        f.write_bytes(b"x" * 2048)
        fc, picked, _ = self._card(tk_root)
        seen = self._dialog(monkeypatch, file=str(f))
        fc.event_generate("<Button-1>", x=3, y=3)
        tk_root.update()
        assert picked == [str(f)]
        assert seen["open"]["filetypes"] == [("All files", "*")]
        assert seen["open"]["initialdir"] == os.path.expanduser("~")
        assert _texts(fc) == [ICON["ok"], "vault.qcx", "2.0 KB  ·  Click to change"]

    def test_the_caller_filetypes_reach_the_dialog(self, tk_root, tmp_path, monkeypatch):
        f = tmp_path / "a.qcx"
        f.write_bytes(b"x" * 10)
        fc, picked, _ = self._card(
            tk_root, filetypes=[("QuantaCrypt", "*.qcx"), ("All files", "*")])
        seen = self._dialog(monkeypatch, file=str(f))
        fc._pick()
        assert seen["open"]["filetypes"] == [("QuantaCrypt", "*.qcx"),
                                             ("All files", "*")]
        # and the filter is a filter, not a gate: the choice still comes back
        assert picked == [str(f)]
        assert _texts(fc) == [ICON["ok"], "a.qcx", "10 B  ·  Click to change"]

    def test_cancelling_the_picker_changes_nothing(self, tk_root, monkeypatch):
        fc, picked, _ = self._card(tk_root, prompt="Select a file", sub="hint")
        self._dialog(monkeypatch, file="")
        fc.event_generate("<Button-1>", x=3, y=3)
        tk_root.update()
        assert picked == []
        assert _texts(fc) == ["+", "Select a file", "hint"]
        assert str(fc.cget("highlightbackground")) == C["border"]

    def test_clicking_any_child_also_opens_the_picker(self, tk_root, tmp_path, monkeypatch):
        f = tmp_path / "a.qcx"
        f.write_bytes(b"x")
        fc, picked, _ = self._card(tk_root)
        self._dialog(monkeypatch, file=str(f))
        for w in (fc._icon, fc._line1, fc._line2):
            w.event_generate("<Button-1>", x=1, y=1)
            tk_root.update()
        assert picked == [str(f)] * 3

    def test_return_and_space_open_the_picker(self, tk_root, tmp_path, monkeypatch):
        f = tmp_path / "a.qcx"
        f.write_bytes(b"x")
        fc, picked, _ = self._card(tk_root)
        self._dialog(monkeypatch, file=str(f))
        _focus(tk_root, fc)
        fc.event_generate("<Return>", when="now")
        fc.event_generate("<space>", when="now")
        tk_root.update()
        assert picked == [str(f), str(f)]

    def test_folder_mode_asks_for_a_folder_and_calls_on_folder(
            self, tk_root, tmp_path, monkeypatch):
        chosen = []
        fc, picked, _ = self._card(tk_root, on_folder=chosen.append)
        self._dialog(monkeypatch, folder=str(tmp_path))
        fc.set_folder_mode(True)
        fc._pick()
        assert chosen == [str(tmp_path)] and picked == []

    def test_folder_mode_falls_back_to_on_select(self, tk_root, tmp_path, monkeypatch):
        fc, picked, _ = self._card(tk_root)
        self._dialog(monkeypatch, folder=str(tmp_path))
        fc.set_folder_mode(True)
        fc._pick()
        assert picked == [str(tmp_path)]

    def test_cancelling_the_folder_picker_changes_nothing(
            self, tk_root, monkeypatch):
        chosen = []
        fc, picked, _ = self._card(tk_root, on_folder=chosen.append)
        self._dialog(monkeypatch, folder="")
        fc.set_folder_mode(True)
        fc._pick()
        assert chosen == [] and picked == []
        assert _texts(fc)[0] == "+"

    def test_folder_mode_can_be_turned_back_off(self, tk_root, tmp_path, monkeypatch):
        f = tmp_path / "a.qcx"
        f.write_bytes(b"x")
        chosen = []
        fc, picked, _ = self._card(tk_root, on_folder=chosen.append)
        self._dialog(monkeypatch, file=str(f), folder=str(tmp_path))
        fc.set_folder_mode(True)
        fc.set_folder_mode(False)
        fc._pick()
        assert picked == [str(f)] and chosen == []

    def test_load_shows_the_name_and_size_and_turns_the_border_green(
            self, tk_root, tmp_path):
        f = tmp_path / "my report.qcx"
        f.write_bytes(b"x" * 1_500_000)
        fc, _, _ = self._card(tk_root)
        fc.load(str(f))
        tk_root.update()
        assert _texts(fc) == [ICON["ok"], "my report.qcx",
                              "1.5 MB  ·  Click to change"]
        assert fc._icon.cget("fg") == C["success"]
        assert fc._line1.cget("fg") == C["text"]
        assert fc._line2.cget("fg") == C["accent_text"]
        assert str(fc.cget("highlightbackground")) == C["success"]

    def test_load_of_a_vanished_file_still_names_it(self, tk_root, tmp_path):
        fc, _, _ = self._card(tk_root)
        fc.load(str(tmp_path / "gone.qcx"))
        tk_root.update()
        assert _texts(fc) == [ICON["ok"], "gone.qcx",
                              "unknown size  ·  Click to change"]
        assert str(fc.cget("highlightbackground")) == C["success"]

    def test_load_of_an_empty_file(self, tk_root, tmp_path):
        f = tmp_path / "empty.qcx"
        f.write_bytes(b"")
        fc, _, _ = self._card(tk_root)
        fc.load(str(f))
        assert fc._line2.cget("text") == "0 B  ·  Click to change"

    def test_load_folder_reports_the_counts(self, tk_root, tmp_path):
        fc, _, _ = self._card(tk_root)
        fc.load_folder(str(tmp_path / "Photos"), 1234, 5_368_709_120)
        tk_root.update()
        assert _texts(fc) == [ICON["ok"], "Photos",
                              "1,234 files  ·  5.4 GB  ·  Click to change"]

    def test_load_folder_while_scanning_says_so(self, tk_root, tmp_path):
        fc, _, _ = self._card(tk_root)
        fc.load_folder(str(tmp_path / "Photos"), 0, 0, scanning=True)
        assert fc._line2.cget("text") == "Scanning folder…"
        assert fc._line2.cget("fg") == C["text3"]
        fc.load_folder(str(tmp_path / "Photos"), 0, 0)
        assert fc._line2.cget("text") == "0 files  ·  0 B  ·  Click to change"

    def test_load_folder_ignores_a_trailing_separator(self, tk_root, tmp_path):
        fc, _, _ = self._card(tk_root)
        fc.load_folder(str(tmp_path / "Photos") + os.sep, 1, 10)
        assert fc._line1.cget("text") == "Photos"

    def test_load_folder_of_the_filesystem_root_falls_back_to_the_path(self, tk_root):
        """Stripping the separator from "/" leaves nothing to show."""
        fc, _, _ = self._card(tk_root)
        fc.load_folder(os.sep, 3, 30)
        assert fc._line1.cget("text") == os.sep

    def test_drop_support_is_only_promised_when_it_exists(self, tk_root):
        fc, _, _ = self._card(tk_root, sub="original")
        fc.set_drop_supported(False, "Drop a file here", "Click to choose a file")
        assert fc._line2.cget("text") == "Click to choose a file"
        fc.set_drop_supported(True, "Drop a file here", "Click to choose a file")
        assert fc._line2.cget("text") == "Drop a file here"

    def test_drop_support_does_not_overwrite_a_selection(self, tk_root, tmp_path):
        f = tmp_path / "a.qcx"
        f.write_bytes(b"x")
        fc, _, _ = self._card(tk_root)
        fc.load(str(f))
        fc.set_drop_supported(True, "Drop a file here", "Click to choose")
        assert fc._line2.cget("text").startswith("1 B")
        # …but the hint is remembered for the next reset
        fc.reset("Select a file")
        assert fc._line2.cget("text") == "Drop a file here"

    def test_reset_returns_the_card_to_its_unselected_look(self, tk_root, tmp_path):
        f = tmp_path / "a.qcx"
        f.write_bytes(b"x")
        fc, _, _ = self._card(tk_root)
        fc.load(str(f))
        fc.reset("Select a .qcv volume", "or drop one here")
        tk_root.update()
        assert _texts(fc) == ["+", "Select a .qcv volume", "or drop one here"]
        assert fc._icon.cget("fg") == C["surface3"]
        assert fc._line1.cget("fg") == C["text3"]
        assert str(fc.cget("highlightbackground")) == C["border"]

    def test_reset_without_a_hint_and_without_a_remembered_one_is_blank(self, tk_root):
        fc, _, _ = self._card(tk_root, sub="original hint")
        fc.reset("Select a file")
        assert fc._line2.cget("text") == ""

    def test_hover_lifts_an_unselected_card_only(self, tk_root, tmp_path):
        fc, _, _ = self._card(tk_root)
        fc.event_generate("<Enter>")
        tk_root.update()
        assert {w.cget("bg") for w in self._widgets(fc)} == {C["surface2"]}
        fc.event_generate("<Leave>")
        tk_root.update()
        assert {w.cget("bg") for w in self._widgets(fc)} == {C["surface"]}
        f = tmp_path / "a.qcx"
        f.write_bytes(b"x")
        fc.load(str(f))
        fc.event_generate("<Enter>")
        tk_root.update()
        assert {w.cget("bg") for w in self._widgets(fc)} == {C["surface"]}, \
            "a chosen file must not flicker under the pointer"

    def test_focus_ring_falls_back_to_the_selection_colour(self, tk_root, tmp_path):
        f = tmp_path / "a.qcx"
        f.write_bytes(b"x")
        fc, _, _ = self._card(tk_root)
        other = tk.Entry(tk_root)
        other.pack()
        _focus(tk_root, fc)
        assert int(fc.cget("highlightthickness")) == 2
        assert str(fc.cget("highlightbackground")) == C["accent_text"]
        _focus(tk_root, other)
        assert int(fc.cget("highlightthickness")) == 1
        assert str(fc.cget("highlightbackground")) == C["border"]
        fc.load(str(f))
        _focus(tk_root, fc)
        _focus(tk_root, other)
        assert str(fc.cget("highlightbackground")) == C["success"]

    def test_disabling_stops_clicks_and_leaves_the_tab_order(self, tk_root, monkeypatch):
        fc, picked, _ = self._card(tk_root)
        self._dialog(monkeypatch, file="/should/not/be/used")
        fc.set_enabled(False)
        assert str(fc.cget("takefocus")) == "0"
        assert str(fc.cget("cursor")) == "arrow"
        for w in self._widgets(fc):
            w.event_generate("<Button-1>", x=1, y=1)
        tk_root.update()
        assert picked == []

    def test_re_enabling_restores_clicks(self, tk_root, tmp_path, monkeypatch):
        f = tmp_path / "a.qcx"
        f.write_bytes(b"x")
        fc, picked, _ = self._card(tk_root)
        self._dialog(monkeypatch, file=str(f))
        fc.set_enabled(False)
        fc.set_enabled(True)
        tk_root.update()
        assert str(fc.cget("takefocus")) == "1"
        assert str(fc.cget("cursor")) == "hand2"
        fc.event_generate("<Button-1>", x=3, y=3)
        tk_root.update()
        assert picked == [str(f)]


# ── WizardSteps ──────────────────────────────────────────────────────────────

@requires_tkinter
class TestWizardSteps:
    """Informational step tracker: done / current / pending, drawn on a
    canvas and skipped in the Tab order."""

    STEPS = ["Choose", "Protect", "Encrypt", "Done"]

    def _steps(self, tk_root, steps=None):
        ws = WizardSteps(tk_root, steps or self.STEPS)
        ws.pack(fill="x")
        tk_root.update()
        return ws

    def _circles(self, ws):
        return [ws.itemcget(i, "fill") for i in ws.find_all()
                if ws.type(i) == "oval"]

    def _labels(self, ws):
        return [ws.itemcget(i, "text") for i in ws.find_all()
                if ws.type(i) == "text"]

    def _lines(self, ws):
        return [ws.itemcget(i, "fill") for i in ws.find_all()
                if ws.type(i) == "line"]

    def test_the_first_step_is_active_and_the_rest_are_pending(self, tk_root):
        ws = self._steps(tk_root)
        assert self._circles(ws) == [C["accent"]] + [C["surface2"]] * 3
        assert self._labels(ws) == ["1", "Choose", "2", "Protect",
                                    "3", "Encrypt", "4", "Done"]
        assert self._lines(ws) == [C["border"]] * 3

    def test_it_is_skipped_in_the_tab_order(self, tk_root):
        ws = self._steps(tk_root)
        assert str(ws.cget("takefocus")) == "0"

    def test_advancing_ticks_the_steps_behind_the_cursor(self, tk_root):
        ws = self._steps(tk_root)
        ws.set_step(2)
        assert self._circles(ws) == [C["success"], C["success"],
                                     C["accent"], C["surface2"]]
        assert self._labels(ws)[:4] == [ICON["ok"], "Choose", ICON["ok"], "Protect"]
        assert self._lines(ws) == [C["success"], C["success"], C["border"]]

    def test_a_step_past_the_end_marks_everything_done(self, tk_root):
        ws = self._steps(tk_root)
        ws.set_step(len(self.STEPS))
        assert self._circles(ws) == [C["success"]] * 4
        assert self._lines(ws) == [C["success"]] * 3
        assert self._labels(ws)[::2] == [ICON["ok"]] * 4

    def test_going_back_un_ticks_a_step(self, tk_root):
        ws = self._steps(tk_root)
        ws.set_step(3)
        ws.set_step(1)
        assert self._circles(ws) == [C["success"], C["accent"],
                                     C["surface2"], C["surface2"]]

    def test_a_single_step_tracker_draws_no_connectors(self, tk_root):
        ws = self._steps(tk_root, ["Only"])
        assert self._lines(ws) == []
        assert self._circles(ws) == [C["accent"]]

    def test_a_tracker_with_no_steps_is_rejected_at_construction(self, tk_root):
        """BAD path: each step gets width/len(steps) points of the canvas, so
        an empty list has no slot width.  It raises where the step list is
        written instead of drawing an empty 0-wide strip into the wizard."""
        before = len(tk_root.winfo_children())
        with pytest.raises(ZeroDivisionError):
            WizardSteps(tk_root, [])
        leftovers = tk_root.winfo_children()[before:]
        assert all(not w.winfo_ismapped() for w in leftovers), \
            "nothing half-drawn reached the screen"

    def test_label_colours_track_the_state(self, tk_root):
        ws = self._steps(tk_root)
        ws.set_step(1)
        colours = [ws.itemcget(i, "fill") for i in ws.find_all()
                   if ws.type(i) == "text"]
        # each step contributes a number/tick then its name
        assert colours[1::2] == [C["success"], C["accent_text"],
                                 C["text3"], C["text3"]]

    def test_a_long_step_name_is_truncated_with_an_ellipsis(self, tk_root):
        ws = self._steps(tk_root, ["Choose", "A ludicrously long step name here"])
        rendered = self._labels(ws)[3]
        assert rendered.endswith("…")
        assert len(rendered) < len("A ludicrously long step name here")
        assert "A ludicrously".startswith(rendered[:8])

    def test_a_short_name_is_left_alone(self, tk_root):
        ws = self._steps(tk_root, ["Pick", "Go"])
        assert self._labels(ws)[1::2] == ["Pick", "Go"]

    def test_the_canvas_never_shrinks_below_one_hundred_points_per_step(self, tk_root):
        ws = self._steps(tk_root)
        assert ws._min_w == 400
        assert int(ws.cget("width")) == 400

    def test_a_resize_redraws_rather_than_stretching(self, tk_root):
        ws = self._steps(tk_root)
        ws.set_step(1)
        before = len(ws.find_all())
        ws.pack_configure(padx=80)
        tk_root.update()
        assert len(ws.find_all()) == before
        assert self._circles(ws)[1] == C["accent"], "state survived the redraw"


# ── copy_secret ──────────────────────────────────────────────────────────────

def _pasteboard_types():
    """The UTIs on the macOS general pasteboard, read independently of the
    code under test."""
    r = subprocess.run(
        ["osascript", "-l", "JavaScript", "-e",
         'ObjC.import("AppKit"); $.NSPasteboard.generalPasteboard.types.js'
         '.map(function (t) { return ObjC.unwrap(t) }).join(",")'],
        capture_output=True, text=True, timeout=15)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip().split(",")


@requires_tkinter
class TestCopySecret:
    """Key material on the clipboard has to be readable by the user's paste
    and invisible to the clipboard managers that would keep it for ever."""

    SHARE = "QCSHARE-1-abandon ability able about above absent"

    def test_the_share_is_on_the_clipboard_to_paste(self, tk_root):
        concealed, change = shared.copy_secret(tk_root, self.SHARE)
        assert tk_root.clipboard_get() == self.SHARE
        assert isinstance(concealed, bool)
        assert (change is None) or isinstance(change, int)

    def test_a_multiline_copy_survives_intact(self, tk_root):
        """"Copy all" puts a whole threshold's worth through in one string."""
        text = "\n".join(f"QCSHARE-{i}-abandon \"ability\" \\ able" for i in range(1, 4))
        shared.copy_secret(tk_root, text)
        assert tk_root.clipboard_get() == text

    @pytest.mark.skipif(sys.platform != "darwin", reason="NSPasteboard only")
    def test_the_copy_is_marked_concealed(self, tk_root):
        """Without the marker the share lands in Maccy/Paste/Alfred/Raycast
        history, which outlives the app, the file and the volume."""
        concealed, change = shared.copy_secret(tk_root, self.SHARE)
        assert concealed is True
        assert isinstance(change, int)
        assert "org.nspasteboard.ConcealedType" in _pasteboard_types()

    @pytest.mark.skipif(sys.platform != "darwin", reason="NSPasteboard only")
    def test_the_share_never_travels_in_argv(self, tk_root, monkeypatch):
        """argv is world-readable through ps; the script goes on stdin."""
        seen = {}
        real = subprocess.run
        def _spy(cmd, *a, **kw):
            seen.setdefault("argv", list(cmd))
            seen.setdefault("stdin", kw.get("input"))
            return real(cmd, *a, **kw)
        monkeypatch.setattr(subprocess, "run", _spy)
        shared.copy_secret(tk_root, self.SHARE)
        assert not any(self.SHARE in str(part) for part in seen["argv"])
        assert self.SHARE in seen["stdin"]

    def test_a_clipboard_that_cannot_be_reached_raises(self, tk_root, monkeypatch):
        """The caller turns this into "⚠ Failed" on the button; it must not
        pass for a successful copy."""
        monkeypatch.setattr(tk_root, "clipboard_clear",
                            lambda: (_ for _ in ()).throw(tk.TclError("no clipboard")))
        with pytest.raises(tk.TclError):
            shared.copy_secret(tk_root, self.SHARE)

    def test_without_the_marker_the_copy_still_happens_and_says_so(
            self, tk_root, monkeypatch):
        """A Linux desktop, or an osascript that refuses: the share still has
        to reach the clipboard, and the caller has to learn it is unmarked."""
        monkeypatch.setattr(shared, "_run_jxa", lambda *a, **k: None)
        concealed, change = shared.copy_secret(tk_root, self.SHARE)
        assert concealed is False and change is None
        assert tk_root.clipboard_get() == self.SHARE

    def test_a_garbled_change_count_counts_as_unmarked(self, tk_root, monkeypatch):
        """No usable changeCount means no way to tell later whether the copy
        is still ours, so it must not be reported as concealed."""
        monkeypatch.setattr(shared, "_run_jxa", lambda *a, **k: "not-a-number\n")
        concealed, change = shared.copy_secret(tk_root, self.SHARE)
        assert concealed is False and change is None
        assert tk_root.clipboard_get() == self.SHARE

    def test_the_timer_copies_and_arms_in_one_step(self, tk_root):
        lbl = tk.Label(tk_root, text="")
        lbl.pack()
        timer = ClipboardTimer(tk_root, lbl, seconds=45)
        concealed = timer.copy(tk_root, self.SHARE)
        assert tk_root.clipboard_get() == self.SHARE
        assert timer._written == self.SHARE
        assert concealed is (sys.platform == "darwin")
        assert lbl.cget("text").startswith("Clipboard clears in 45s")
        timer.cancel()


# ── ClipboardTimer ───────────────────────────────────────────────────────────

@requires_tkinter
class TestClipboardTimer:
    """A copied share must not sit on the clipboard for ever: the countdown
    is visible, cancellable, and clears the clipboard when it runs out."""

    def _timer(self, tk_root, seconds=60):
        lbl = tk.Label(tk_root, text="")
        lbl.pack()
        tk_root.update()
        return ClipboardTimer(tk_root, lbl, seconds=seconds), lbl

    def test_start_shows_the_countdown(self, tk_root):
        timer, lbl = self._timer(tk_root, seconds=42)
        timer.start()
        tk_root.update()
        assert lbl.cget("text") == "Clipboard clears in 42s"
        assert lbl.cget("fg") == C["text3"]
        assert timer._job is not None
        timer.cancel()

    def test_each_tick_counts_down(self, tk_root):
        timer, lbl = self._timer(tk_root, seconds=3)
        timer.start()
        assert lbl.cget("text") == "Clipboard clears in 3s"
        timer._tick()
        assert lbl.cget("text") == "Clipboard clears in 2s"
        timer._tick()
        assert lbl.cget("text") == "Clipboard clears in 1s"
        timer.cancel()

    def test_running_out_clears_the_clipboard(self, tk_root):
        timer, lbl = self._timer(tk_root, seconds=1)
        tk_root.clipboard_clear()
        tk_root.clipboard_append("share-1 of 3: abandon ability able")
        assert tk_root.clipboard_get() == "share-1 of 3: abandon ability able"
        timer.start("share-1 of 3: abandon ability able")   # start() renders 1s
        timer._tick()          # 0s left — fires the clear
        tk_root.update()
        with pytest.raises(tk.TclError):
            tk_root.clipboard_get()
        assert lbl.cget("text") == f"Clipboard cleared {ICON['ok']}"
        assert lbl.cget("fg") == C["success"]
        assert timer._job is None

    def test_a_zero_second_timer_clears_immediately(self, tk_root):
        timer, lbl = self._timer(tk_root, seconds=0)
        tk_root.clipboard_clear()
        tk_root.clipboard_append("secret")
        timer.start("secret")
        with pytest.raises(tk.TclError):
            tk_root.clipboard_get()
        assert lbl.cget("text") == f"Clipboard cleared {ICON['ok']}"

    def test_cancel_stops_the_countdown_and_wipes_the_label(self, tk_root):
        timer, lbl = self._timer(tk_root, seconds=60)
        timer.start()
        timer.cancel()
        tk_root.update()
        assert lbl.cget("text") == ""
        assert timer._job is None and timer._remain == 0
        # and nothing is left to fire
        assert not [j for j in tk_root.tk.call("after", "info")]

    def test_cancel_is_safe_before_a_start(self, tk_root):
        timer, lbl = self._timer(tk_root)
        timer.cancel()
        assert timer._job is None and lbl.cget("text") == ""

    def test_restarting_replaces_the_previous_countdown(self, tk_root):
        timer, lbl = self._timer(tk_root, seconds=10)
        timer.start()
        first = timer._job
        timer.start()
        assert timer._job != first
        assert len(tk_root.tk.call("after", "info")) == 1, "no stacked timers"
        assert lbl.cget("text") == "Clipboard clears in 10s"
        timer.cancel()

    def test_a_stale_job_id_does_not_break_cancel(self, tk_root):
        timer, _ = self._timer(tk_root)
        timer._job = "after#never-existed"
        timer.cancel()
        assert timer._job is None

    def test_a_destroyed_label_does_not_stop_the_countdown(self, tk_root):
        """Losing the countdown label must not lose the wipe: the label is
        cosmetic, clearing the clipboard is the security-relevant half."""
        timer, lbl = self._timer(tk_root, seconds=2)
        tk_root.clipboard_clear()
        tk_root.clipboard_append("secret")
        timer.start("secret")
        lbl.destroy()
        timer._remain = 1
        timer._tick()
        assert timer._job is not None, "still counting"
        timer._tick()
        with pytest.raises(tk.TclError):
            tk_root.clipboard_get()

    def test_an_interpreter_that_is_going_away_stops_the_countdown(self, tk_root):
        """Last-ditch guard: once Tk itself refuses to answer there is no
        window left to wipe a clipboard for."""
        timer, lbl = self._timer(tk_root, seconds=5)
        timer.start()
        timer.cancel()
        lbl.winfo_exists = lambda: (_ for _ in ()).throw(tk.TclError("gone"))
        timer._remain = 5
        timer._tick()
        assert timer._job is None

    def test_a_destroyed_label_does_not_stop_the_clipboard_being_cleared(
            self, tk_root):
        timer, lbl = self._timer(tk_root, seconds=1)
        tk_root.clipboard_clear()
        tk_root.clipboard_append("secret")
        timer.start("secret")
        lbl.destroy()
        timer._clear()
        with pytest.raises(tk.TclError):
            tk_root.clipboard_get()

    def test_cancel_survives_a_destroyed_label(self, tk_root):
        timer, lbl = self._timer(tk_root, seconds=5)
        timer.start()
        lbl.destroy()
        timer.cancel()
        assert timer._job is None

    def test_the_cleared_notice_wipes_itself_after_a_moment(self, tk_root):
        timer, lbl = self._timer(tk_root, seconds=1)
        tk_root.clipboard_clear()
        tk_root.clipboard_append("secret")
        timer.start("secret")
        timer._clear()
        assert lbl.cget("text") == f"Clipboard cleared {ICON['ok']}"
        assert _pump_until(tk_root, lambda: lbl.cget("text") == "", timeout=5.0)

    # ── Only this timer's own copy is ever wiped (F-010) ──────────────────

    def test_a_clipboard_the_user_has_since_replaced_is_left_alone(self, tk_root):
        """The clipboard belongs to the whole machine: an account number
        copied out of Safari at t=20 must survive the share's t=60 wipe."""
        timer, lbl = self._timer(tk_root, seconds=1)
        timer.start("share-1 of 3: abandon ability able")
        tk_root.clipboard_clear()
        tk_root.clipboard_append("4111 1111 1111 1111")
        timer._tick()
        assert tk_root.clipboard_get() == "4111 1111 1111 1111", "not ours to wipe"
        assert lbl.cget("text") == "Clipboard already changed"
        assert lbl.cget("fg") == C["text3"]

    def test_a_timer_that_recorded_nothing_wipes_nothing(self, tk_root):
        """No record of what was copied means no way to know the clipboard is
        still ours, so the only safe move is to leave it."""
        timer, lbl = self._timer(tk_root, seconds=1)
        tk_root.clipboard_clear()
        tk_root.clipboard_append("someone else's data")
        timer._clear()
        assert tk_root.clipboard_get() == "someone else's data"
        assert lbl.cget("text") == "Clipboard already changed"

    def test_a_copy_is_only_ever_settled_once(self, tk_root):
        timer, lbl = self._timer(tk_root, seconds=1)
        tk_root.clipboard_clear()
        tk_root.clipboard_append("secret")
        timer.start("secret")
        timer._clear()
        assert timer._written is None and timer._change is None
        tk_root.clipboard_append("something the user copied after")
        timer._clear()
        assert tk_root.clipboard_get() == "something the user copied after"

    def test_cancel_forgets_the_copy(self, tk_root):
        timer, _ = self._timer(tk_root, seconds=5)
        timer.start("secret")
        timer.cancel()
        assert timer._written is None and timer._change is None

    def test_detaching_the_label_keeps_the_wipe_armed(self, tk_root):
        """A card that has just been saved drops its countdown label, but
        the share it copied moments before is still on the clipboard and
        the wipe is the only thing that will take it off."""
        timer, lbl = self._timer(tk_root, seconds=5)
        tk_root.clipboard_clear()
        tk_root.clipboard_append("secret")
        timer.start("secret")
        timer.detach_label()
        assert lbl.cget("text") == ""
        assert timer._job is not None, "still counting"
        assert timer._written == "secret", "the copy is still known"
        timer._remain = 0
        timer._tick()
        with pytest.raises(tk.TclError):
            tk_root.clipboard_get()
        assert timer._job is None and timer._written is None

    def test_a_detached_timer_never_touches_the_label_again(self, tk_root):
        timer, lbl = self._timer(tk_root, seconds=5)
        timer.start("secret")
        timer.detach_label()
        lbl.config(text="something the caller put here")
        timer._tick()
        timer._clear()
        timer.cancel()
        assert lbl.cget("text") == "something the caller put here"

    def test_an_unmarked_copy_says_the_clipboard_may_keep_it(self, tk_root):
        """A countdown that cannot be trusted must not read like one that can:
        without the concealed marker a clipboard manager keeps the share for
        ever and the 60 seconds protect nothing."""
        timer, lbl = self._timer(tk_root, seconds=42)
        timer.start("secret", concealed=False)
        assert lbl.cget("text") == \
            "Clipboard clears in 42s  ·  a clipboard manager may keep it"
        timer.cancel()
        timer.start("secret", concealed=True)
        assert lbl.cget("text") == "Clipboard clears in 42s"
        timer.cancel()

    def test_a_refused_wipe_is_reported_not_claimed(self, tk_root, monkeypatch):
        """Saying "cleared" when the share is still on the clipboard is a
        false security claim about key material."""
        timer, lbl = self._timer(tk_root, seconds=1)
        tk_root.clipboard_clear()
        tk_root.clipboard_append("secret")
        timer.start("secret")
        monkeypatch.setattr(tk_root, "clipboard_clear",
                            lambda: (_ for _ in ()).throw(tk.TclError("no clipboard")))
        timer._clear()
        assert tk_root.clipboard_get() == "secret", "still on the clipboard"
        assert lbl.cget("text") == f"Couldn't clear the clipboard {ICON['warn']}"
        assert lbl.cget("fg") == C["warning"]

    def test_the_failure_notice_stays_up(self, tk_root, monkeypatch):
        """The success notice fades after two seconds; a failure the user has
        to act on must not."""
        # seconds=0 so start() fires the wipe outright and leaves no pending
        # tick to redraw the label under the assertion.
        timer, lbl = self._timer(tk_root, seconds=0)
        tk_root.clipboard_clear()
        tk_root.clipboard_append("secret")
        monkeypatch.setattr(tk_root, "clipboard_clear",
                            lambda: (_ for _ in ()).throw(tk.TclError("no clipboard")))
        timer.start("secret")
        assert lbl.cget("text") == f"Couldn't clear the clipboard {ICON['warn']}"
        assert not _pump_until(tk_root, lambda: lbl.cget("text") == "", timeout=3.0)

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS pasteboard")
    def test_the_macos_wipe_goes_by_pasteboard_change_count(self, tk_root, monkeypatch):
        """Tk answers clipboard_get() from its own buffer and never notices
        another app taking the macOS pasteboard, so the changeCount is the
        only witness that the copy is still ours."""
        seen = {}
        def _kept(change):
            seen["change"] = change
            return None            # the user has copied something else since
        monkeypatch.setattr(shared, "clear_pasteboard_if_unchanged", _kept)
        timer, lbl = self._timer(tk_root, seconds=1)
        timer.start("secret", change=4242)
        timer._tick()
        assert seen["change"] == 4242
        assert lbl.cget("text") == "Clipboard already changed"


# ── teardown guards ──────────────────────────────────────────────────────────

@requires_tkinter
class TestTeardownGuards:
    """Every timer-cancelling path is wrapped because a window can be torn
    down out from under a pending job.  These pin what happens when Tk itself
    starts refusing calls: the widget forgets the job and carries on rather
    than raising out of a callback nobody is watching."""

    @staticmethod
    def _refuse(monkeypatch, obj, name="after_cancel"):
        monkeypatch.setattr(obj, name,
                            lambda *a, **k: (_ for _ in ()).throw(
                                tk.TclError("application has been destroyed")))

    def test_progress_bar_forgets_jobs_it_could_not_cancel(self, tk_root, monkeypatch):
        bar = StagedProgressBar(tk_root, [("a", 1), ("b", 1)])
        bar.pack(fill="x")
        tk_root.update()
        bar.start()
        bar.advance(0, "a")
        assert bar._time_job and bar._pulse_job
        self._refuse(monkeypatch, bar)
        bar.stop()
        assert bar._time_job is None and bar._pulse_job is None

    def test_progress_bar_re_arms_the_pulse_after_a_failed_cancel(
            self, tk_root, monkeypatch):
        """advance() cancels the previous dot pulse before starting the next
        one.  When Tk refuses that cancel the repaint must still finish — the
        label carries on animating and exactly one pulse id is remembered,
        rather than the progress callback dying half-way through."""
        bar = StagedProgressBar(tk_root, [("a", 1), ("b", 1)])
        bar.pack(fill="x")
        tk_root.update()
        bar.start()
        bar.advance(0, "Deriving key")
        first = bar._pulse_job
        assert first is not None
        self._refuse(monkeypatch, bar)
        bar.advance(0, "Deriving key")
        assert bar._pulse_job not in (None, first), "a fresh pulse was armed"
        assert bar._stage_lbl.cget("text") == "Deriving key.", "still animating"
        assert bar._pct == 0.0, "the rest of the repaint ran too"
        monkeypatch.undo()
        bar.stop()

    def test_strength_bar_re_arms_the_debounce_after_a_failed_cancel(
            self, tk_root, monkeypatch):
        bar, var = _new_strength_bar(tk_root)
        var.set("a")
        first = bar._refresh_job
        assert first is not None
        self._refuse(monkeypatch, bar)
        var.set("ab")
        assert bar._refresh_job not in (None, first)

    def test_score_for_survives_a_failed_debounce_cancel(self, tk_root, monkeypatch):
        bar, var = _new_strength_bar(tk_root)
        var.set("Tr0ub4dor&3")
        assert bar._refresh_job is not None
        self._refuse(monkeypatch, bar)
        # The literal 4, not a value recomputed here: a submit that swallowed
        # the failure and returned the "nothing scored yet" 0 would pass a
        # test that compared score_for() against _score() and nothing else.
        assert bar.score_for("Tr0ub4dor&3") == 4
        assert bar._refresh_job is None
        assert bar._last == ("Tr0ub4dor&3", 4, "Strong", "")

    def _timer(self, tk_root, seconds=60):
        lbl = tk.Label(tk_root, text="")
        lbl.pack()
        tk_root.update()
        return ClipboardTimer(tk_root, lbl, seconds=seconds), lbl

    def test_clipboard_timer_forgets_a_job_it_could_not_cancel(
            self, tk_root, monkeypatch):
        timer, lbl = self._timer(tk_root, seconds=30)
        timer.start()
        assert timer._job is not None
        self._refuse(monkeypatch, tk_root)
        timer.cancel()
        assert timer._job is None and timer._remain == 0
        assert lbl.cget("text") == ""

    def test_clipboard_timer_cancels_even_when_the_label_cannot_answer(
            self, tk_root):
        timer, lbl = self._timer(tk_root, seconds=30)
        timer.start()
        lbl.winfo_exists = lambda: (_ for _ in ()).throw(tk.TclError("gone"))
        timer.cancel()
        assert timer._job is None and timer._remain == 0

    def test_the_wipe_happens_even_when_the_label_cannot_answer(self, tk_root):
        timer, lbl = self._timer(tk_root, seconds=1)
        tk_root.clipboard_clear()
        tk_root.clipboard_append("secret")
        timer.start("secret")
        lbl.winfo_exists = lambda: (_ for _ in ()).throw(tk.TclError("gone"))
        timer._clear()
        with pytest.raises(tk.TclError):
            tk_root.clipboard_get()
        assert timer._job is None

    def test_a_clipboard_that_refuses_to_clear_is_reported_not_claimed(
            self, tk_root, monkeypatch):
        """Announcing a wipe that did not happen is a false security claim
        about a Shamir share, so the failure is named instead."""
        timer, lbl = self._timer(tk_root, seconds=1)
        tk_root.clipboard_clear()
        tk_root.clipboard_append("secret")
        timer.start("secret")
        monkeypatch.setattr(tk_root, "clipboard_clear",
                            lambda: (_ for _ in ()).throw(tk.TclError("no clipboard")))
        timer._clear()
        assert tk_root.clipboard_get() == "secret", "still on the clipboard"
        assert lbl.cget("text") == f"Couldn't clear the clipboard {ICON['warn']}"

    def test_a_grab_that_can_no_longer_be_taken_is_not_fatal(self, tk_root):
        """The previous modal may have hidden itself while the nested dialog
        was up, and Tk refuses a grab for a window that is not viewable.  The
        refusal is simulated rather than staged — macOS Tk is lenient about
        off-screen toplevels — but the contract is the same: the answer the
        user gave must survive a failed hand-back."""
        holder = tk.Toplevel(tk_root)
        holder.geometry("120x60-4000-4000")
        tk_root.update()
        holder.grab_set()

        def _break_grab_then_cancel(win):
            holder.withdraw()
            holder.grab_set = lambda: (_ for _ in ()).throw(
                tk.TclError("grab failed: window not viewable"))
            _dialog_buttons(win)[-1]._fire()

        state = _when_dialog(tk_root, _break_grab_then_cancel, skip=(holder,))
        assert confirm(tk_root, "T", "M") is False
        assert state["error"] is None
        assert tk_root.grab_current() is None, "the grab was not handed back"
        holder.destroy()


class TestClipboardWipeAll:
    """Run 18 F-205: a quit took the countdown with it and left the share on
    the clipboard."""

    def _timer(self, monkeypatch, on_clipboard):
        import types
        from quantacrypt.ui.shared import ClipboardTimer
        root = types.SimpleNamespace(jobs=[], cleared=0)
        root.after = lambda ms, fn: root.jobs.append(fn) or len(root.jobs)
        root.after_cancel = lambda job: None
        root.clipboard_clear = lambda: setattr(root, "cleared", root.cleared + 1)
        t = ClipboardTimer(root, None, seconds=60)
        monkeypatch.setattr(t, "_clipboard_text", lambda: on_clipboard)
        return t, root

    def test_wipe_all_clears_only_the_copies_still_ours(self, monkeypatch):
        from quantacrypt.ui.shared import ClipboardTimer
        ClipboardTimer._armed.clear()
        ours, root_a = self._timer(monkeypatch, "share-one")
        theirs, root_b = self._timer(monkeypatch, "an account number")
        ours.start("share-one", concealed=True); theirs.start("share-two", concealed=True)
        assert ClipboardTimer._armed == {ours, theirs}
        ClipboardTimer.wipe_all()
        assert root_a.cleared == 1 and root_b.cleared == 0          # theirs changed meanwhile
        assert ClipboardTimer._armed == set() and ours._written is None and ours._job is None

    def test_cancel_and_the_countdown_disarm(self, monkeypatch):
        from quantacrypt.ui.shared import ClipboardTimer
        ClipboardTimer._armed.clear()
        t, root = self._timer(monkeypatch, "x")
        t.start("x"); assert t in ClipboardTimer._armed
        t.cancel();   assert t not in ClipboardTimer._armed
        t.start("x"); t._remain = 0; t._tick()
        assert t not in ClipboardTimer._armed and root.cleared == 1


class TestRecentFilesClearReportsFailure:
    def test_clear_is_false_when_the_list_cannot_be_rewritten(self, monkeypatch, tmp_path):
        """Run 18 F-208: "Clear" removed the rows and left the stored list of
        decrypted-file paths on disk."""
        from quantacrypt.ui import shared
        monkeypatch.setattr(shared.RecentFiles, "_resolve_path", classmethod(lambda cls: str(tmp_path / "recent.json")))
        assert shared.RecentFiles.clear() is True
        def refuse(path, entries):
            raise PermissionError(13, "Permission denied", path)
        monkeypatch.setattr(shared, "_write_private_json", refuse)
        assert shared.RecentFiles.clear() is False
