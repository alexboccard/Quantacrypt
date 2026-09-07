"""Behavioural tests for the launcher home screen and the update checker.

`ui/launcher.py` and `ui/updater.py` are the two screens the user meets before
any credential is typed, and until now almost nothing here was exercised: the
quit-with-volumes-mounted guard, the drag-and-drop dispatcher, the recent-files
list, the inspect dialog and the whole update banner were all untested.

Everything below drives real widgets and asserts on rendered text, widget state,
persisted preferences or the arguments the launcher hands a wizard.  Nothing
asserts on source text, and nothing asserts "a mock was called" where the effect
is observable somewhere else.
"""

import json
import os
import sys
import threading
import time
import tkinter as tk
import urllib.error
from types import SimpleNamespace

import pytest

from quantacrypt.core import crypto as cc
from quantacrypt.core.errors import friendly_error
from quantacrypt.ui import updater
from quantacrypt.ui.shared import C, MOD, FlatButton, fmt_size

from tests.conftest import HAS_TKINTER, requires_tkinter, _widget_texts

pytestmark = requires_tkinter


# ── Helpers ──────────────────────────────────────────────────────────────────

def _fake_qcx(path, meta, prefix=b""):
    """Write a .qcx whose *envelope* is real but whose payload is absent.

    ``load_pkg`` only parses the trailing metadata envelope, so this gives
    exact control over the metadata the launcher renders without paying for an
    Argon2id derivation per test.
    """
    blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
    path.write_bytes(prefix + cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
    return str(path)


def _spy_wizard(record):
    """A stand-in wizard class that records how the launcher constructed it."""
    class _Spy:
        def __init__(self, master, **kw):
            record.append({"master": master, **kw})
    return _Spy


def _flat_buttons(widget, out=None):
    out = [] if out is None else out
    if isinstance(widget, FlatButton):
        out.append(widget)
    for child in widget.winfo_children():
        _flat_buttons(child, out)
    return out


def _button(widget, text):
    """The one FlatButton in ``widget``'s tree whose label contains ``text``."""
    hits = [b for b in _flat_buttons(widget) if text in str(b.cget("text"))]
    assert len(hits) == 1, f"expected exactly one {text!r} button, got {len(hits)}"
    return hits[0]


def _labels_with(widget, text, out=None):
    """Every widget in the tree whose -text option contains ``text``."""
    out = [] if out is None else out
    try:
        cur = str(widget.cget("text"))
    except Exception:
        cur = ""
    if text and text in cur:
        out.append(widget)
    for child in widget.winfo_children():
        _labels_with(child, text, out)
    return out


def _show_offscreen(app):
    """Map the window — Tk silently drops ``event_generate`` on unmapped
    windows — but park it where it cannot disturb the desktop."""
    app.deiconify()
    app.geometry("-4000-4000")
    app.update()


def _click(widget):
    widget.event_generate("<Button-1>", when="now")
    widget.update()


def _press(button):
    """Click a FlatButton, which fires on release and only inside its bounds."""
    button.update_idletasks()
    assert button.winfo_width() > 1, "the button must be laid out to be clickable"
    button.event_generate("<Button-1>", x=1, y=1, when="now")
    button.event_generate("<ButtonRelease-1>", x=1, y=1, when="now")
    button.update()


def _pump(widget, predicate, timeout=3.0):
    """Spin the Tk event loop until ``predicate`` holds; returns whether it did."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        widget.update()
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


def _take_focus(widget, timeout=2.0):
    """Give ``widget`` the real input focus, which Tk requires before it will
    route a key event anywhere.  Returns whether the window manager complied —
    an off-screen window is not always allowed to take focus."""
    top = widget.winfo_toplevel()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        top.focus_force()
        widget.focus_force()
        widget.update()
        if widget.focus_get() is widget:
            return True
        time.sleep(0.01)
    return widget.focus_get() is widget


def _ready(win):
    """Wait for a freshly created Toplevel to be viewable — Tk silently drops
    ``event_generate`` on a window the WM has not mapped yet."""
    win.update_idletasks()
    _pump(win, lambda: bool(win.winfo_viewable()))
    win.update()
    return win


def _inspect_window(app):
    wins = [w for w in app.winfo_children() if isinstance(w, tk.Toplevel)]
    assert len(wins) == 1, f"expected one inspect window, found {len(wins)}"
    return wins[0]


@pytest.fixture
def prefs_dir(tmp_path, monkeypatch):
    """Point every persisted store at the test's tmp dir."""
    if not HAS_TKINTER:
        pytest.skip("needs real tkinter")
    from quantacrypt.ui.shared import AppPrefs, RecentFiles, RecentVolumes
    monkeypatch.setattr(AppPrefs, "_PATH", str(tmp_path / "prefs.json"))
    monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
    monkeypatch.setattr(RecentVolumes, "_PATH", str(tmp_path / "recent-vol.json"))
    return tmp_path


@pytest.fixture
def make_launcher(tk_root, prefs_dir, monkeypatch):
    """Build real ``LauncherApp`` instances with the network check disabled.

    Each launcher gets its own withdrawn Toplevel as master so a test can watch
    ``_quit_app`` destroy it without taking the shared root down.
    """
    import quantacrypt.ui.launcher as launcher_mod
    monkeypatch.setattr(launcher_mod, "check_for_update", lambda *a, **k: None,
                        raising=False)
    monkeypatch.setattr(updater, "check_for_update", lambda *a, **k: None)
    built = []

    def _make(dnd=None, withdraw=True):
        monkeypatch.setattr(launcher_mod, "_DND_FILES", dnd)
        holder = tk.Toplevel(tk_root)
        holder.withdraw()
        app = launcher_mod.LauncherApp(holder)
        if withdraw:
            app.withdraw()
        app.update()
        built.append((app, holder))
        return app

    yield _make

    for app, holder in built:
        for w in (app, holder):
            try:
                if w.winfo_exists():
                    w.destroy()
            except tk.TclError:
                pass


@pytest.fixture
def wizards(monkeypatch):
    """Replace the three wizard windows with recorders.

    Constructing the real wizards costs seconds and opens windows; what the
    launcher owes them is a master, a close callback, a centre point and (for
    two of them) the file to open — all of which the recorder captures.
    """
    import quantacrypt.ui.decryptor as dec_mod
    import quantacrypt.ui.encryptor as enc_mod
    import quantacrypt.ui.volume_manager as vol_mod
    rec = {"decrypt": [], "encrypt": [], "volumes": []}
    monkeypatch.setattr(dec_mod, "DecryptorApp", _spy_wizard(rec["decrypt"]))
    monkeypatch.setattr(enc_mod, "EncryptorApp", _spy_wizard(rec["encrypt"]))
    monkeypatch.setattr(vol_mod, "VolumeManagerApp", _spy_wizard(rec["volumes"]))
    return rec


@pytest.fixture
def dialogs(monkeypatch):
    """Capture the tkinter dialogs the launcher raises, and script the answers."""
    from tkinter import filedialog, messagebox
    state = {
        "errors": [], "asked": [],
        "answer": True,          # what askyesno returns
        "picked": "",            # what askopenfilename returns
    }

    def _showerror(title, message, **kw):
        state["errors"].append((title, message))

    def _askyesno(title, message, **kw):
        state["asked"].append((title, message))
        return state["answer"]

    monkeypatch.setattr(messagebox, "showerror", _showerror)
    monkeypatch.setattr(messagebox, "askyesno", _askyesno)
    monkeypatch.setattr(filedialog, "askopenfilename",
                        lambda **kw: state["picked"])
    return state


@pytest.fixture
def fuse_stub(monkeypatch):
    """Script ``get_mounted_volumes`` / ``unmount_volume`` for the quit guard."""
    from quantacrypt.core import fuse_ops
    state = {"mounted": [], "unmounted": [], "fail": set(), "raise_list": None}

    def _get():
        if state["raise_list"] is not None:
            raise state["raise_list"]
        return list(state["mounted"])

    def _unmount(mp):
        if mp in state["fail"]:
            raise RuntimeError("device busy")
        state["unmounted"].append(mp)

    monkeypatch.setattr(fuse_ops, "get_mounted_volumes", _get)
    monkeypatch.setattr(fuse_ops, "unmount_volume", _unmount)
    return state


# ══ launcher.py ═══════════════════════════════════════════════════════════════


class TestQuitGuard:
    """``_quit_app`` must never destroy the app while a FUSE volume is still
    mounted: the kernel has in-flight writes and Finder keeps a dangling
    mountpoint.  It unmounts first, and abandons the quit if it cannot."""

    def test_quit_with_nothing_mounted_destroys_the_app(self, make_launcher,
                                                        fuse_stub, dialogs):
        app = make_launcher()
        master = app.master
        app._quit_app()
        assert not master.winfo_exists()
        assert dialogs["asked"] == [], "no prompt when nothing is mounted"

    def test_quit_still_works_when_fuse_is_unavailable(self, make_launcher,
                                                       fuse_stub, dialogs):
        """A build without fusepy raises on the import; quitting must not
        become impossible because the volume feature is missing."""
        fuse_stub["raise_list"] = ImportError("no fusepy here")
        app = make_launcher()
        master = app.master
        app._quit_app()
        assert not master.winfo_exists()
        assert dialogs["asked"] == [], "an unavailable FUSE is not a mounted volume"
        assert fuse_stub["unmounted"] == []

    def test_declining_the_prompt_keeps_the_app_and_the_mounts(
            self, make_launcher, fuse_stub, dialogs):
        fuse_stub["mounted"] = ["/Volumes/Secret"]
        dialogs["answer"] = False
        app = make_launcher()
        master = app.master
        app._quit_app()
        assert master.winfo_exists(), "declining must not destroy the app"
        assert fuse_stub["unmounted"] == []

    def test_single_mount_prompt_names_the_mountpoint(self, make_launcher,
                                                      fuse_stub, dialogs):
        fuse_stub["mounted"] = ["/Volumes/Secret"]
        dialogs["answer"] = False
        app = make_launcher()
        app._quit_app()
        title, message = dialogs["asked"][0]
        assert title == "Volumes mounted"
        assert "/Volumes/Secret" in message
        # Documents actual behaviour: the singular branch drops the count, so
        # the sentence reads "You still have volume mounted" (see bugsFound).
        assert "You still have volume mounted" in message
        assert "…" not in message

    def test_prompt_pluralises_and_truncates_a_long_mount_list(
            self, make_launcher, fuse_stub, dialogs):
        fuse_stub["mounted"] = [f"/Volumes/v{i}" for i in range(7)]
        dialogs["answer"] = False
        app = make_launcher()
        app._quit_app()
        _, message = dialogs["asked"][0]
        assert "You still have 7 volumes mounted" in message
        assert "/Volumes/v4" in message      # fifth entry is the last listed
        assert "/Volumes/v5" not in message  # sixth and beyond are elided
        assert "…" in message

    def test_exactly_five_mounts_are_listed_without_an_ellipsis(
            self, make_launcher, fuse_stub, dialogs):
        """Boundary below the 5-entry cap."""
        fuse_stub["mounted"] = [f"/Volumes/v{i}" for i in range(5)]
        dialogs["answer"] = False
        app = make_launcher()
        app._quit_app()
        _, message = dialogs["asked"][0]
        assert all(f"/Volumes/v{i}" in message for i in range(5))
        assert "…" not in message

    def test_six_mounts_are_the_first_to_elide(self, make_launcher, fuse_stub,
                                               dialogs):
        """Boundary immediately above the cap: the sixth entry is the first one
        that has to be replaced by the ellipsis."""
        fuse_stub["mounted"] = [f"/Volumes/v{i}" for i in range(6)]
        dialogs["answer"] = False
        app = make_launcher()
        app._quit_app()
        _, message = dialogs["asked"][0]
        assert "You still have 6 volumes mounted" in message
        assert all(f"/Volumes/v{i}" in message for i in range(5))
        assert "/Volumes/v5" not in message
        assert "…" in message

    def test_the_window_close_button_runs_the_quit_guard(
            self, make_launcher, fuse_stub, dialogs):
        """WM_DELETE_WINDOW must reach ``_quit_app``, not a bare destroy — the
        red close button is the most likely way to quit with a volume up."""
        fuse_stub["mounted"] = ["/Volumes/Secret"]
        dialogs["answer"] = False
        app = make_launcher()
        master = app.master
        # Invoking the registered Tcl command is exactly what the window
        # manager does when the user clicks the close button.
        app.tk.call(app.wm_protocol("WM_DELETE_WINDOW"))
        assert [t for t, _ in dialogs["asked"]] == ["Volumes mounted"]
        assert master.winfo_exists(), "a bare destroy would have taken it down"
        assert fuse_stub["unmounted"] == []

    def test_accepting_unmounts_everything_then_destroys(self, make_launcher,
                                                         fuse_stub, dialogs):
        fuse_stub["mounted"] = ["/Volumes/a", "/Volumes/b", "/Volumes/c"]
        dialogs["answer"] = True
        app = make_launcher()
        master = app.master
        app._quit_app()
        assert fuse_stub["unmounted"] == ["/Volumes/a", "/Volumes/b", "/Volumes/c"]
        assert not master.winfo_exists()

    def test_a_failed_unmount_aborts_the_quit_and_names_the_volume(
            self, make_launcher, fuse_stub, dialogs):
        fuse_stub["mounted"] = ["/Volumes/a", "/Volumes/busy", "/Volumes/c"]
        fuse_stub["fail"] = {"/Volumes/busy"}
        dialogs["answer"] = True
        app = make_launcher()
        master = app.master
        app._quit_app()
        assert master.winfo_exists(), "a failed unmount must abort the quit"
        # The loop keeps going past the failure so the healthy ones still come down.
        assert fuse_stub["unmounted"] == ["/Volumes/a", "/Volumes/c"]
        title, message = dialogs["errors"][0]
        assert title == "Unmount failed"
        assert "/Volumes/busy: device busy" in message
        assert "/Volumes/a" not in message


class TestDropDispatch:
    """A drop must open every .qcx / .qcv in the payload and refuse everything
    else with a visible, self-clearing hint."""

    def test_dropping_a_qcx_opens_the_decryptor(self, make_launcher, wizards,
                                                prefs_dir, tmp_path):
        qcx = _fake_qcx(tmp_path / "one.qcx", {"mode": "single", "version": 1})
        app = make_launcher()
        app._on_drop(SimpleNamespace(data=qcx))
        assert [c["qcx_path"] for c in wizards["decrypt"]] == [qcx]
        assert wizards["volumes"] == []

    def test_dropping_a_qcv_opens_the_volume_manager(self, make_launcher,
                                                     wizards, tmp_path):
        qcv = tmp_path / "disk.qcv"
        qcv.write_bytes(b"not parsed by the launcher")
        app = make_launcher()
        app._on_drop(SimpleNamespace(data=str(qcv)))
        assert [c["volume_path"] for c in wizards["volumes"]] == [str(qcv)]
        assert wizards["decrypt"] == []

    def test_extension_match_is_case_insensitive(self, make_launcher, wizards,
                                                 tmp_path):
        qcv = tmp_path / "SHOUTY.QCV"
        qcv.write_bytes(b"x")
        app = make_launcher()
        app._on_drop(SimpleNamespace(data=str(qcv)))
        assert [c["volume_path"] for c in wizards["volumes"]] == [str(qcv)]

    def test_dropping_an_unsupported_file_shows_an_error_hint(
            self, make_launcher, wizards, tmp_path):
        txt = tmp_path / "notes.txt"
        txt.write_text("hello")
        app = make_launcher(dnd="DND_Files")
        app._on_drop(SimpleNamespace(data=str(txt)))
        assert ".qcx" in app._hint.cget("text")
        assert str(app._hint.cget("fg")) == C["error"]
        assert wizards["decrypt"] == [] and wizards["volumes"] == []

    def test_dropping_a_path_that_does_not_exist_is_refused(
            self, make_launcher, wizards, tmp_path):
        """The extension is right but the file is gone — isfile() is the guard."""
        app = make_launcher()
        app._on_drop(SimpleNamespace(data=str(tmp_path / "ghost.qcx")))
        assert str(app._hint.cget("fg")) == C["error"]
        assert wizards["decrypt"] == []

    def test_dropping_a_directory_named_like_a_volume_is_refused(
            self, make_launcher, wizards, tmp_path):
        """``isfile`` and not ``exists`` is the guard: a bundle or a folder
        someone renamed to .qcv would otherwise be handed to the FUSE code."""
        folder = tmp_path / "looks-like.qcv"
        folder.mkdir()
        app = make_launcher(dnd="DND_Files")
        app._on_drop(SimpleNamespace(data=str(folder)))
        assert wizards["volumes"] == [] and wizards["decrypt"] == []
        assert str(app._hint.cget("fg")) == C["error"]
        assert ".qcx" in app._hint.cget("text")

    def test_dropping_nothing_is_refused(self, make_launcher, wizards):
        """Zero paths: splitlist("") yields an empty tuple, not a crash."""
        app = make_launcher()
        app._on_drop(SimpleNamespace(data=""))
        assert str(app._hint.cget("fg")) == C["error"]
        assert wizards["decrypt"] == [] and wizards["volumes"] == []

    def test_a_multi_drop_opens_one_wizard_per_accepted_file(
            self, make_launcher, wizards, tmp_path):
        qcx = _fake_qcx(tmp_path / "a.qcx", {"mode": "single", "version": 1})
        qcv = tmp_path / "b.qcv"
        qcv.write_bytes(b"x")
        junk = tmp_path / "c.txt"
        junk.write_text("skip me")
        app = make_launcher()
        # Tcl list syntax is what tkinterdnd2 hands over for a multi-selection.
        app._on_drop(SimpleNamespace(
            data=" ".join(f"{{{p}}}" for p in (qcx, str(qcv), str(junk)))))
        assert [c["qcx_path"] for c in wizards["decrypt"]] == [qcx]
        # The trailing paths are dispatched from the Tk event loop, not inline.
        assert _pump(app, lambda: len(wizards["volumes"]) == 1)
        assert [c["volume_path"] for c in wizards["volumes"]] == [str(qcv)]

    def test_paths_with_spaces_and_quotes_survive_the_drop(
            self, make_launcher, wizards, tmp_path):
        odd = tmp_path / "a folder"
        odd.mkdir()
        qcx = _fake_qcx(odd / "my 'quoted' ünicode.qcx",
                        {"mode": "single", "version": 1})
        app = make_launcher()
        app._on_drop(SimpleNamespace(data="{%s}" % qcx))
        assert [c["qcx_path"] for c in wizards["decrypt"]] == [qcx]

    def test_a_broken_tcl_split_falls_back_to_the_first_path(
            self, make_launcher, wizards, tmp_path, monkeypatch):
        """Some Tk builds raise on non-ASCII Tcl lists; the fallback keeps the
        first dropped path rather than losing the drop entirely."""
        first = _fake_qcx(tmp_path / "first one.qcx",
                          {"mode": "single", "version": 1})
        second = tmp_path / "second.qcv"
        second.write_bytes(b"x")
        app = make_launcher()

        class _BrokenSplit:
            def __init__(self, real):
                self._real = real

            def __getattr__(self, name):
                return getattr(self._real, name)

            def splitlist(self, *_a):
                raise RuntimeError("bad Tcl encoding")

        monkeypatch.setattr(app, "tk", _BrokenSplit(app.tk))
        app._on_drop(SimpleNamespace(data="  {%s} {%s}  " % (first, second)))
        assert [c["qcx_path"] for c in wizards["decrypt"]] == [first]
        assert wizards["volumes"] == [], "the fallback keeps only the first path"

    def test_dnd_registration_wires_the_real_drop_handler(
            self, make_launcher, wizards, tmp_path, monkeypatch):
        """tkinterdnd2 injects these two methods at runtime; the launcher must
        hand it the dispatcher that actually opens files."""
        import quantacrypt.ui.launcher as launcher_mod
        registered, bound = [], {}
        monkeypatch.setattr(launcher_mod.LauncherApp, "drop_target_register",
                            lambda self, *t: registered.append(t), raising=False)
        monkeypatch.setattr(launcher_mod.LauncherApp, "dnd_bind",
                            lambda self, seq, fn: bound.__setitem__(seq, fn),
                            raising=False)
        make_launcher(dnd="DND_Files")
        assert registered == [("DND_Files",)]
        qcx = _fake_qcx(tmp_path / "wired.qcx", {"mode": "single", "version": 1})
        bound["<<Drop>>"](SimpleNamespace(data=qcx))
        assert [c["qcx_path"] for c in wizards["decrypt"]] == [qcx]

    def test_a_failing_dnd_registration_still_yields_a_usable_launcher(
            self, make_launcher, monkeypatch):
        """A broken drag-and-drop extension must not take the window with it."""
        import quantacrypt.ui.launcher as launcher_mod
        bound = []
        monkeypatch.setattr(
            launcher_mod.LauncherApp, "drop_target_register",
            lambda self, *t: (_ for _ in ()).throw(RuntimeError("no XDND")),
            raising=False)
        monkeypatch.setattr(launcher_mod.LauncherApp, "dnd_bind",
                            lambda self, seq, fn: bound.append(seq), raising=False)
        app = make_launcher(dnd="DND_Files")
        assert app.winfo_exists()
        assert "QuantaCrypt" in _widget_texts(app)
        # Documents actual behaviour: _build() paints the drop promise before
        # registration is attempted, so the hint outlives the failure — and
        # nothing is listening for <<Drop>>, so the promise cannot be kept.
        assert bound == [], "registration failed before the handler was bound"
        assert "drop" in app._hint.cget("text").lower()


class TestHintReset:
    """An error hint is temporary — it must revert to the standing message so
    the launcher does not sit in a red state forever."""

    @staticmethod
    def _capture_after(app, monkeypatch):
        scheduled = []
        monkeypatch.setattr(app, "after",
                            lambda ms, fn=None, *a: scheduled.append((ms, fn, a)))
        return scheduled

    def test_an_error_hint_reverts_to_the_drop_promise(self, make_launcher,
                                                       monkeypatch):
        app = make_launcher(dnd="DND_Files")
        scheduled = self._capture_after(app, monkeypatch)
        app._set_hint("Drop a .qcx or .qcv file", error=True)
        assert str(app._hint.cget("fg")) == C["error"]
        (delay, fn, _), = scheduled
        assert delay == 6000
        fn()
        assert app._hint.cget("text") == \
            "You can also drop a .qcx or .qcv file onto this window."
        assert str(app._hint.cget("fg")) == C["text3"]

    def test_an_error_hint_reverts_to_nothing_without_drag_and_drop(
            self, make_launcher, monkeypatch):
        """Without tkinterdnd2 the standing hint is empty — reverting to the
        drop promise would advertise a capability the build does not have."""
        app = make_launcher(dnd=None)
        scheduled = self._capture_after(app, monkeypatch)
        app._set_hint("nope", error=True)
        scheduled[0][1]()
        assert app._hint.cget("text") == ""

    def test_a_plain_hint_is_left_alone(self, make_launcher, monkeypatch):
        app = make_launcher(dnd="DND_Files")
        scheduled = self._capture_after(app, monkeypatch)
        app._set_hint("Pick a file to begin")
        assert scheduled == [], "only an error hint schedules its own reversal"
        assert app._hint.cget("text") == "Pick a file to begin"
        assert str(app._hint.cget("fg")) == C["text3"]


class TestEntryPointRows:
    """Each of the three rows is a real target: clickable anywhere, keyboard
    reachable, and it shows focus on its own border."""

    def test_clicking_the_encrypt_row_opens_the_encryptor(self, make_launcher,
                                                          wizards):
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        _click(app._enc_card)
        assert len(wizards["encrypt"]) == 1

    def test_clicking_a_child_label_also_activates_the_row(self, make_launcher,
                                                           wizards):
        """The description text covers most of the row; clicking it must not
        be a dead zone."""
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        label = _labels_with(app._vol_card, "works like a folder")[0]
        _click(label)
        assert len(wizards["volumes"]) == 1

    def test_return_on_a_focused_row_activates_it(self, make_launcher, wizards):
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        if not _take_focus(app._enc_card):
            pytest.skip("the window manager would not focus the off-screen window")
        app._enc_card.event_generate("<Return>", when="now")
        app.update()
        assert len(wizards["encrypt"]) == 1

    def test_space_on_a_focused_row_activates_it(self, make_launcher, wizards):
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        if not _take_focus(app._vol_card):
            pytest.skip("the window manager would not focus the off-screen window")
        app._vol_card.event_generate("<space>", when="now")
        app.update()
        assert len(wizards["volumes"]) == 1

    def test_clicking_the_decrypt_row_raises_the_file_picker(
            self, make_launcher, wizards, dialogs, tmp_path):
        qcx = _fake_qcx(tmp_path / "row.qcx", {"mode": "single", "version": 1})
        dialogs["picked"] = qcx
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        _click(app._dec_card)
        assert [c["qcx_path"] for c in wizards["decrypt"]] == [qcx]

    def test_focus_draws_a_ring_and_blur_removes_it(self, make_launcher):
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        row = app._enc_card
        assert int(row.cget("highlightthickness")) == 1
        row.event_generate("<FocusIn>", when="now")
        app.update()
        assert int(row.cget("highlightthickness")) == 2
        assert str(row.cget("highlightbackground")) == C["accent_text"]
        row.event_generate("<FocusOut>", when="now")
        app.update()
        assert int(row.cget("highlightthickness")) == 1
        assert str(row.cget("highlightbackground")) == C["border"]

    def test_hover_tints_an_unfocused_row(self, make_launcher):
        # C["surface3"] and C["border"] are the same hex in the shipped
        # palette, so a row already sitting at its resting colour cannot show
        # whether the handler ran.  Painting a sentinel first is what makes
        # "the hover handler writes surface3 / border" an observable claim.
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        row = app._dec_card
        sentinel = "#ff00ff"
        row.config(highlightbackground=sentinel)
        row.event_generate("<Enter>", when="now")
        app.update()
        assert str(row.cget("highlightbackground")) == C["surface3"]
        row.config(highlightbackground=sentinel)
        row.event_generate("<Leave>", when="now")
        app.update()
        assert str(row.cget("highlightbackground")) == C["border"]

    def test_hover_never_overwrites_the_focus_ring(self, make_launcher):
        """The other side of the hover conditional.  A row that already owns
        the focus must keep its ring, or a stray mouse move would erase a
        keyboard user's position."""
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        row = app._enc_card
        if not _take_focus(row):
            pytest.skip("the window manager would not focus the off-screen window")
        assert str(row.cget("highlightbackground")) == C["accent_text"]
        row.event_generate("<Enter>", when="now")
        app.update()
        assert str(row.cget("highlightbackground")) == C["accent_text"]
        row.event_generate("<Leave>", when="now")
        app.update()
        assert str(row.cget("highlightbackground")) == C["accent_text"]

    def test_the_last_used_mode_is_the_accented_row(self, make_launcher,
                                                    wizards):
        """Opening the volume manager must move the accent for the next launch."""
        first = make_launcher()
        first._open_volumes()
        second = make_launcher()
        assert str(_button(second._vol_card, "Manage volumes").cget("bg")) == \
            C["accent"]
        assert str(_button(second._enc_card, "Encrypt a file").cget("bg")) == \
            C["surface2"]

    def test_encrypt_is_the_accented_row_on_a_fresh_install(self, make_launcher):
        app = make_launcher()
        assert str(_button(app._enc_card, "Encrypt a file").cget("bg")) == \
            C["accent"]

    def test_the_footer_advertises_the_version_and_the_four_accelerators(
            self, make_launcher):
        """The footer is the only place the shortcuts are discoverable, so it
        has to name the keys that TestKeyboardShortcuts proves actually fire."""
        from quantacrypt import __version__
        from quantacrypt.ui.shared import accel
        app = make_launcher()
        footer = [t for t in _widget_texts(app) if t.startswith(f"v{__version__}")]
        assert len(footer) == 1, "exactly one footer line, carrying the version"
        for key, label in [("E", "Encrypt"), ("D", "Decrypt"),
                           ("M", "Volumes"), ("I", "Inspect")]:
            assert f"{accel(key)} {label}" in footer[0]
        assert accel("V") not in footer[0], "Volumes answers to M, never to V"


class TestKeyboardShortcuts:
    """The four accelerators the footer advertises, and the macOS-only ⌘W/⌘Q
    pair.  Binding them in ``__init__`` is not the contract — the contract is
    that pressing them does the thing, so every test here presses a real key."""

    @staticmethod
    def _focused(app):
        """Tk delivers a key event to the toplevel's focus widget, so
        something inside the window has to hold real focus first."""
        _show_offscreen(app)
        if not _take_focus(app._enc_card):
            pytest.skip("the window manager would not focus the off-screen window")
        return app

    def test_the_encrypt_accelerator_opens_the_encryptor(self, make_launcher,
                                                         wizards):
        app = self._focused(make_launcher(withdraw=False))
        app.event_generate(f"<{MOD}-e>", when="now")
        app.update()
        call, = wizards["encrypt"]
        assert call["master"] is app.master
        assert app.state() == "withdrawn"

    def test_the_volumes_accelerator_is_m_not_v(self, make_launcher, wizards):
        """⌘V is Paste on macOS, so Volumes deliberately answers to M — and
        must not answer to V."""
        app = self._focused(make_launcher(withdraw=False))
        app.event_generate(f"<{MOD}-v>", when="now")
        app.update()
        assert wizards["volumes"] == []
        app.event_generate(f"<{MOD}-m>", when="now")
        app.update()
        assert len(wizards["volumes"]) == 1

    def test_the_decrypt_accelerator_raises_the_picker(self, make_launcher,
                                                       wizards, dialogs,
                                                       tmp_path):
        qcx = _fake_qcx(tmp_path / "shortcut.qcx", {"mode": "single", "version": 1})
        dialogs["picked"] = qcx
        app = self._focused(make_launcher(withdraw=False))
        app.event_generate(f"<{MOD}-d>", when="now")
        app.update()
        assert [c["qcx_path"] for c in wizards["decrypt"]] == [qcx]

    def test_the_inspect_accelerator_opens_the_file_info_window(
            self, make_launcher, dialogs, tmp_path):
        qcx = _fake_qcx(tmp_path / "peek.qcx", {"mode": "single", "version": 1})
        dialogs["picked"] = qcx
        app = self._focused(make_launcher(withdraw=False))
        app.event_generate(f"<{MOD}-i>", when="now")
        app.update()
        win = _inspect_window(app)
        assert "peek.qcx" in _widget_texts(win)
        win.destroy()

    @pytest.mark.skipif(sys.platform != "darwin",
                        reason="Control is the modifier off macOS, so there is "
                               "no second accelerator to accept")
    def test_control_is_accepted_as_well_as_command(self, make_launcher, wizards):
        """Muscle memory from Windows/Linux still has to work on macOS."""
        app = self._focused(make_launcher(withdraw=False))
        app.event_generate("<Control-e>", when="now")
        app.update()
        assert len(wizards["encrypt"]) == 1

    @pytest.mark.skipif(sys.platform != "darwin",
                        reason="⌘W / ⌘Q are bound only on macOS")
    @pytest.mark.parametrize("key", ["w", "q"])
    def test_the_macos_quit_keys_go_through_the_volume_guard(
            self, make_launcher, fuse_stub, dialogs, key):
        fuse_stub["mounted"] = ["/Volumes/Secret"]
        dialogs["answer"] = False
        app = self._focused(make_launcher(withdraw=False))
        master = app.master
        app.event_generate(f"<Command-{key}>", when="now")
        app.update()
        assert [t for t, _ in dialogs["asked"]] == ["Volumes mounted"]
        assert master.winfo_exists(), "declining must leave the app running"
        assert fuse_stub["unmounted"] == []

    @pytest.mark.skipif(sys.platform != "darwin",
                        reason="the Control alias only exists on macOS")
    @pytest.mark.parametrize("key", ["w", "q"])
    def test_control_is_not_an_alias_for_quit(self, make_launcher, fuse_stub,
                                              dialogs, key):
        """``also_control=False`` on the quit pair: Ctrl+W is "close tab" in
        every browser, and must never take a mounted volume down with it."""
        fuse_stub["mounted"] = ["/Volumes/Secret"]
        dialogs["answer"] = False
        app = self._focused(make_launcher(withdraw=False))
        master = app.master
        app.event_generate(f"<Control-{key}>", when="now")
        app.update()
        assert dialogs["asked"] == []
        assert master.winfo_exists()
        assert app.state() == "normal"
        # Same keystroke with ⌘ does reach the guard, so the silence above is
        # the missing binding and not a key event that never arrived.
        app.event_generate(f"<Command-{key}>", when="now")
        app.update()
        assert [t for t, _ in dialogs["asked"]] == ["Volumes mounted"]


class TestRecentList:
    """The recent list shows at most three still-existing files, labels how each
    was locked, and can be cleared."""

    def _write_recent(self, prefs_dir, entries):
        (prefs_dir / "recent.json").write_text(json.dumps(entries))

    def _entry(self, prefs_dir, name="doc.qcx", **kw):
        p = prefs_dir / name
        p.write_bytes(b"x" * 10)
        entry = {"path": str(p), "ts": 0}
        entry.update(kw)
        return entry

    def test_nothing_is_rendered_when_there_are_no_recents(self, make_launcher):
        app = make_launcher()
        assert app._recent_frame.winfo_children() == []

    def test_one_recent_file_shows_its_name_folder_and_mode(self, make_launcher,
                                                            prefs_dir):
        entry = self._entry(prefs_dir, ts=1_700_000_000)
        self._write_recent(prefs_dir, [entry])
        app = make_launcher()
        texts = _widget_texts(app._recent_frame)
        assert "RECENTLY DECRYPTED" in texts
        assert "doc.qcx" in texts
        assert str(prefs_dir) in texts
        assert any(t.startswith("Password  ·  ") for t in texts)
        assert not any("more" in t for t in texts)

    def test_a_shamir_entry_is_labelled_with_its_threshold(self, make_launcher,
                                                           prefs_dir):
        self._write_recent(prefs_dir, [self._entry(
            prefs_dir, mode="shamir", threshold=2, total=3)])
        app = make_launcher()
        assert "Split key (2 of 3)" in _widget_texts(app._recent_frame)

    def test_a_shamir_entry_without_parameters_falls_back_to_password(
            self, make_launcher, prefs_dir):
        """An entry written by an older build has no threshold/total; showing
        "Split key (0 of 0)" would be worse than saying nothing precise."""
        self._write_recent(prefs_dir, [self._entry(
            prefs_dir, mode="shamir", threshold=0, total=0)])
        app = make_launcher()
        assert "Password" in _widget_texts(app._recent_frame)
        assert not any("Split key" in t for t in _widget_texts(app._recent_frame))

    def test_a_missing_timestamp_renders_the_mode_alone(self, make_launcher,
                                                        prefs_dir):
        self._write_recent(prefs_dir, [self._entry(prefs_dir, ts=0)])
        app = make_launcher()
        assert "Password" in _widget_texts(app._recent_frame)

    def test_an_out_of_range_timestamp_does_not_break_the_row(
            self, make_launcher, prefs_dir):
        """A corrupt recent.json must degrade to "no date", not crash the
        launcher on startup."""
        self._write_recent(prefs_dir, [self._entry(prefs_dir, ts=1e300)])
        app = make_launcher()
        texts = _widget_texts(app._recent_frame)
        assert "Password" in texts
        assert "doc.qcx" in texts

    @pytest.mark.parametrize("count,expect_more", [(1, None), (2, None),
                                                   (3, None), (4, "1 more"),
                                                   (6, "3 more")])
    def test_the_visible_list_is_capped_at_three(self, make_launcher, prefs_dir,
                                                 count, expect_more):
        entries = [self._entry(prefs_dir, name=f"f{i}.qcx") for i in range(count)]
        self._write_recent(prefs_dir, entries)
        app = make_launcher()
        texts = _widget_texts(app._recent_frame)
        shown = [t for t in texts if t.endswith(".qcx")]
        assert len(shown) == min(count, 3)
        more = [t for t in texts if "more (use Decrypt to browse)" in t]
        if expect_more is None:
            assert more == []
        else:
            assert expect_more in more[0]

    def test_a_corrupt_recent_store_renders_nothing_and_still_builds(
            self, make_launcher, prefs_dir):
        """recent.json is hand-editable and survives crashes; a truncated one
        must not stop the launcher from opening."""
        (prefs_dir / "recent.json").write_text("{ this is not a list")
        app = make_launcher()
        assert app._recent_frame.winfo_children() == []
        assert "QuantaCrypt" in _widget_texts(app)

    def test_a_null_path_in_the_store_is_skipped_and_the_rest_shown(
            self, make_launcher, prefs_dir):
        """``{"path": null}`` used to be a TypeError inside the constructor —
        the app could not start until the JSON was hand-edited."""
        self._write_recent(prefs_dir, [{"path": None, "ts": 0}, {"path": [1]},
                                       self._entry(prefs_dir)])
        app = make_launcher()
        texts = _widget_texts(app._recent_frame)
        assert "doc.qcx" in texts
        assert "QuantaCrypt" in _widget_texts(app)

    def test_a_recent_store_that_raises_does_not_stop_the_launcher(
            self, make_launcher, monkeypatch):
        """Whatever the store does, the window opens: the same guard the
        wizard-close path already had."""
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "load", classmethod(
            lambda cls: (_ for _ in ()).throw(RuntimeError("store exploded"))))
        app = make_launcher()
        assert app.winfo_exists()
        assert "QuantaCrypt" in _widget_texts(app)

    def test_a_very_long_filename_is_rendered_in_full(self, make_launcher,
                                                      prefs_dir):
        """Long names come from real users (scanned documents, exports); the
        row must show the name, not a truncation the code invented."""
        name = "a" * 180 + ".qcx"
        self._write_recent(prefs_dir, [self._entry(prefs_dir, name=name)])
        app = make_launcher()
        assert name in _widget_texts(app._recent_frame)

    def test_entries_whose_file_vanished_are_dropped(self, make_launcher,
                                                     prefs_dir):
        alive = self._entry(prefs_dir, name="alive.qcx")
        dead = self._entry(prefs_dir, name="dead.qcx")
        os.remove(dead["path"])
        self._write_recent(prefs_dir, [dead, alive])
        app = make_launcher()
        texts = _widget_texts(app._recent_frame)
        assert "alive.qcx" in texts
        assert "dead.qcx" not in texts

    def test_rebuilding_replaces_the_rows_instead_of_stacking_them(
            self, make_launcher, prefs_dir):
        self._write_recent(prefs_dir, [self._entry(prefs_dir)])
        app = make_launcher()
        app._build_recent()
        app._build_recent()
        texts = _widget_texts(app._recent_frame)
        assert texts.count("RECENTLY DECRYPTED") == 1
        assert texts.count("doc.qcx") == 1

    def test_clear_empties_the_store_and_the_list(self, make_launcher, prefs_dir):
        from quantacrypt.ui.shared import RecentFiles
        self._write_recent(prefs_dir, [self._entry(prefs_dir)])
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        _press(_button(app._recent_frame, "Clear"))
        app.update()
        assert RecentFiles.load() == []
        assert app._recent_frame.winfo_children() == []

    def test_clicking_a_recent_row_opens_that_file(self, make_launcher, wizards,
                                                   prefs_dir):
        qcx = _fake_qcx(prefs_dir / "recent.qcx", {"mode": "single", "version": 1})
        self._write_recent(prefs_dir, [{"path": qcx, "ts": 0}])
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        _click(_labels_with(app._recent_frame, "recent.qcx")[0])
        assert [c["qcx_path"] for c in wizards["decrypt"]] == [qcx]

    def test_a_recent_row_shows_a_focus_ring(self, make_launcher, prefs_dir):
        self._write_recent(prefs_dir, [self._entry(prefs_dir)])
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        row = _labels_with(app._recent_frame, "doc.qcx")[0].master.master.master
        assert int(row.cget("highlightthickness")) == 1
        row.event_generate("<FocusIn>", when="now")
        app.update()
        assert int(row.cget("highlightthickness")) == 2
        assert str(row.cget("highlightbackground")) == C["accent_text"]
        row.event_generate("<FocusOut>", when="now")
        app.update()
        assert int(row.cget("highlightthickness")) == 1
        assert str(row.cget("highlightbackground")) == C["border"]
        # Sentinel first: surface3 and border are the same hex in the shipped
        # palette, so without it neither hover assertion could fail.
        sentinel = "#ff00ff"
        row.config(highlightbackground=sentinel)
        row.event_generate("<Enter>", when="now")
        app.update()
        assert str(row.cget("highlightbackground")) == C["surface3"]
        row.config(highlightbackground=sentinel)
        row.event_generate("<Leave>", when="now")
        app.update()
        assert str(row.cget("highlightbackground")) == C["border"]


class TestSafeOpenWizard:
    """Hiding the launcher before a wizard is built used to strand the user with
    an invisible app when construction failed."""

    def test_a_successful_open_leaves_the_launcher_hidden(self, make_launcher,
                                                          dialogs):
        app = make_launcher(withdraw=False)
        app._safe_open_wizard(lambda: None)
        assert app.state() == "withdrawn"
        assert dialogs["errors"] == []

    def test_a_failing_open_restores_the_launcher_and_explains(
            self, make_launcher, dialogs):
        exc = FileNotFoundError(2, "No such file", "/gone.qcx")
        app = make_launcher(withdraw=False)

        def _boom():
            raise exc

        app._safe_open_wizard(_boom)
        assert app.state() == "normal", "the launcher must come back"
        title, message = dialogs["errors"][0]
        assert title == "Cannot open window"
        assert friendly_error(exc) in message


class TestNavigation:
    """What the launcher hands each wizard, and what it remembers afterwards."""

    def test_open_encryptor_passes_master_close_and_centre(self, make_launcher,
                                                           wizards):
        from quantacrypt.ui.shared import AppPrefs
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        expected = (app.winfo_x() + app.winfo_width() // 2,
                    app.winfo_y() + app.winfo_height() // 2)
        app._open_encryptor()
        call, = wizards["encrypt"]
        assert call["master"] is app.master
        assert call["on_close"] == app.deiconify
        assert call["center_at"] == expected
        assert AppPrefs.get("last_mode") == "encrypt"
        assert app.state() == "withdrawn"

    def test_a_wizard_that_cannot_be_built_brings_the_launcher_back(
            self, make_launcher, dialogs, monkeypatch):
        """The BAD path of ``_open_encryptor``: a constructor that raises must
        leave the user with a visible window and an explanation rather than a
        hidden process.  What it does leave behind is asserted below."""
        from quantacrypt.ui.shared import AppPrefs
        import quantacrypt.ui.encryptor as enc_mod
        AppPrefs.set("last_mode", "decrypt")
        exc = RuntimeError("Tk ran out of colormap entries")

        def _boom(*a, **kw):
            raise exc

        monkeypatch.setattr(enc_mod, "EncryptorApp", _boom)
        app = make_launcher(withdraw=False)
        app._open_encryptor()
        assert app.state() == "normal", "the launcher must not stay hidden"
        title, message = dialogs["errors"][0]
        assert title == "Cannot open window"
        assert friendly_error(exc) in message
        # Documents actual behaviour: the mode is remembered before the wizard
        # is built, so a failed open still moves the accent (see bugsFound).
        assert AppPrefs.get("last_mode") == "encrypt"

    def test_open_volumes_forwards_the_volume_path(self, make_launcher, wizards):
        from quantacrypt.ui.shared import AppPrefs
        app = make_launcher()
        app._open_volumes(volume_path="/tmp/disk.qcv")
        call, = wizards["volumes"]
        assert call["volume_path"] == "/tmp/disk.qcv"
        assert call["on_close"] == app.deiconify
        assert AppPrefs.get("last_mode") == "volumes"

    def test_open_volumes_without_a_path_opens_the_manager_empty(
            self, make_launcher, wizards):
        app = make_launcher()
        app._open_volumes()
        assert wizards["volumes"][0]["volume_path"] is None

    def test_cancelling_the_decrypt_picker_changes_nothing(
            self, make_launcher, wizards, dialogs):
        from quantacrypt.ui.shared import AppPrefs
        AppPrefs.set("last_mode", "encrypt")
        dialogs["picked"] = ""
        app = make_launcher(withdraw=False)
        app._open_decryptor()
        assert wizards["decrypt"] == []
        assert AppPrefs.get("last_mode") == "encrypt", "cancelling is not a choice"
        assert app.state() == "normal", "the launcher must stay visible"
        assert dialogs["errors"] == []

    def test_picking_an_unreadable_file_reports_it_and_stays_put(
            self, make_launcher, wizards, dialogs, tmp_path):
        from quantacrypt.ui.shared import AppPrefs
        AppPrefs.set("last_mode", "volumes")
        junk = tmp_path / "garbage.qcx"
        junk.write_bytes(b"definitely not a qcx")
        dialogs["picked"] = str(junk)
        app = make_launcher(withdraw=False)
        app._open_decryptor()
        assert wizards["decrypt"] == []
        assert AppPrefs.get("last_mode") == "volumes", "a failed open is not a use"
        assert app.state() == "normal"
        title, message = dialogs["errors"][0]
        assert title == "Cannot open file"
        assert "garbage.qcx" in message
        assert "Not a QuantaCrypt file" in message

    def test_picking_a_valid_file_opens_it_in_the_decryptor(
            self, make_launcher, wizards, dialogs, tmp_path):
        from quantacrypt.ui.shared import AppPrefs
        qcx = _fake_qcx(tmp_path / "picked.qcx",
                        {"mode": "shamir", "version": 1,
                         "threshold": 2, "total": 3})
        dialogs["picked"] = qcx
        app = make_launcher(withdraw=False)
        app._open_decryptor()
        call, = wizards["decrypt"]
        assert call["qcx_path"] == qcx
        assert call["payload"]["meta"]["threshold"] == 2
        assert call["on_close"] == app._on_wizard_close
        assert AppPrefs.get("last_mode") == "decrypt"
        assert app.state() == "withdrawn"

    def test_open_qcx_reports_an_unreadable_file(self, make_launcher, wizards,
                                                 dialogs, tmp_path):
        from quantacrypt.ui.shared import AppPrefs
        AppPrefs.set("last_mode", "encrypt")
        junk = tmp_path / "broken.qcx"
        junk.write_bytes(cc.MAGIC + b"\x00\x00\x00\x09" + b"{not json")
        app = make_launcher(withdraw=False)
        app._open_qcx(str(junk))
        assert wizards["decrypt"] == []
        assert app.state() == "normal"
        assert "broken.qcx" in dialogs["errors"][0][1]
        # A rejected file must leave no trace: the launcher is still visible,
        # nothing was opened, and the remembered mode is untouched.
        assert AppPrefs.get("last_mode") == "encrypt"

    def test_open_qcx_reports_a_missing_file(self, make_launcher, wizards,
                                             dialogs, tmp_path):
        app = make_launcher(withdraw=False)
        app._open_qcx(str(tmp_path / "never-existed.qcx"))
        assert wizards["decrypt"] == []
        _, message = dialogs["errors"][0]
        assert friendly_error(FileNotFoundError()) in message

    def test_open_qcx_handles_a_quoted_unicode_path(self, make_launcher,
                                                    wizards, tmp_path):
        d = tmp_path / "a dir"
        d.mkdir()
        qcx = _fake_qcx(d / "l'été \"2026\".qcx", {"mode": "single", "version": 1})
        app = make_launcher()
        app._open_qcx(qcx)
        assert [c["qcx_path"] for c in wizards["decrypt"]] == [qcx]


class TestWizardClose:
    """Closing a decrypt wizard must both bring the launcher back and pick up
    the recent entry the wizard just wrote."""

    def test_closing_reshows_the_launcher_and_refreshes_recents(
            self, make_launcher, prefs_dir):
        app = make_launcher(withdraw=False)
        assert app._recent_frame.winfo_children() == []
        app.withdraw()
        newly = prefs_dir / "just-decrypted.qcx"
        newly.write_bytes(b"x")
        (prefs_dir / "recent.json").write_text(
            json.dumps([{"path": str(newly), "ts": 0}]))
        app._on_wizard_close()
        assert app.state() == "normal"
        assert "just-decrypted.qcx" in _widget_texts(app._recent_frame)

    def test_a_broken_recent_list_does_not_keep_the_launcher_hidden(
            self, make_launcher, monkeypatch):
        """Contract is "no raise": the window coming back matters more than the
        recent list, so a failure there is swallowed on purpose."""
        app = make_launcher(withdraw=False)
        app.withdraw()
        monkeypatch.setattr(app, "_build_recent",
                            lambda: (_ for _ in ()).throw(OSError("disk gone")))
        app._on_wizard_close()
        assert app.state() == "normal"


class TestInspectDialog:
    """Inspect answers "what is this file?" without a credential, so every row
    it shows must come from the cleartext envelope only."""

    def test_cancelling_the_picker_opens_no_window(self, make_launcher, dialogs):
        dialogs["picked"] = ""
        app = make_launcher()
        app._inspect_file()
        assert [w for w in app.winfo_children() if isinstance(w, tk.Toplevel)] == []
        assert dialogs["errors"] == [], "cancelling is not an error"

    def test_an_unreadable_file_is_reported_without_a_window(
            self, make_launcher, dialogs, tmp_path):
        junk = tmp_path / "nope.qcx"
        junk.write_bytes(b"random bytes")
        dialogs["picked"] = str(junk)
        app = make_launcher()
        app._inspect_file()
        assert [w for w in app.winfo_children() if isinstance(w, tk.Toplevel)] == []
        title, message = dialogs["errors"][0]
        assert title == "Cannot read file"
        assert "nope.qcx" in message

    def test_a_password_file_reports_its_size_format_and_argon2(
            self, make_launcher, dialogs, tmp_path):
        qcx = _fake_qcx(tmp_path / "secret.qcx",
                        {"mode": "single", "version": 1, "argon_salt": "AAAA"})
        dialogs["picked"] = qcx
        app = make_launcher()
        app._inspect_file()
        win = _inspect_window(app)
        texts = _widget_texts(win)
        assert "secret.qcx" in texts
        assert fmt_size(os.path.getsize(qcx)) in texts
        assert "v1" in texts
        assert "Password" in texts
        assert any("Argon2id" in t for t in texts)
        assert not any("Includes its own decryptor" in t for t in texts)
        assert win.title().endswith("secret.qcx")
        win.destroy()

    def test_a_password_file_without_a_salt_omits_the_argon_row(
            self, make_launcher, dialogs, tmp_path):
        qcx = _fake_qcx(tmp_path / "nosalt.qcx", {"mode": "single", "version": 1})
        dialogs["picked"] = qcx
        app = make_launcher()
        app._inspect_file()
        win = _inspect_window(app)
        assert not any("Argon2id" in t for t in _widget_texts(win))
        win.destroy()

    def test_a_split_key_file_spells_out_the_threshold(self, make_launcher,
                                                       dialogs, tmp_path):
        qcx = _fake_qcx(tmp_path / "split.qcx",
                        {"mode": "shamir", "version": 1,
                         "threshold": 3, "total": 5})
        dialogs["picked"] = qcx
        app = make_launcher()
        app._inspect_file()
        win = _inspect_window(app)
        assert "Split key: any 3 of 5 shares open it" in _widget_texts(win)
        win.destroy()

    def test_a_self_executing_file_is_flagged_as_portable(self, make_launcher,
                                                          dialogs, tmp_path):
        qcx = _fake_qcx(tmp_path / "portable.qcx",
                        {"mode": "single", "version": 1, "payload_offset": 4096},
                        prefix=b"MZ" + b"\x00" * 200)
        dialogs["picked"] = qcx
        app = make_launcher()
        app._inspect_file()
        win = _inspect_window(app)
        assert "Includes its own decryptor" in _widget_texts(win)
        win.destroy()

    def test_a_zero_payload_offset_is_not_portable(self, make_launcher, dialogs,
                                                   tmp_path):
        """Offset 0 is what a plain .qcx records; only a non-zero prefix means
        a decryptor is bundled in front of the payload."""
        qcx = _fake_qcx(tmp_path / "plain.qcx",
                        {"mode": "single", "version": 1, "payload_offset": 0})
        dialogs["picked"] = qcx
        app = make_launcher()
        app._inspect_file()
        win = _inspect_window(app)
        assert not any("Includes its own decryptor" in t
                       for t in _widget_texts(win))
        win.destroy()

    def test_a_versionless_envelope_renders_an_unknown_format(
            self, make_launcher, dialogs, tmp_path):
        qcx = _fake_qcx(tmp_path / "old.qcx", {"mode": "single"})
        dialogs["picked"] = qcx
        app = make_launcher()
        app._inspect_file()
        win = _inspect_window(app)
        assert "v?" in _widget_texts(win)
        win.destroy()

    def test_a_unicode_quoted_filename_is_shown_verbatim(self, make_launcher,
                                                         dialogs, tmp_path):
        name = "rapport 'final' — ünïcode.qcx"
        qcx = _fake_qcx(tmp_path / name, {"mode": "single", "version": 1})
        dialogs["picked"] = qcx
        app = make_launcher()
        app._inspect_file()
        win = _inspect_window(app)
        texts = _widget_texts(win)
        assert name in texts
        assert qcx in texts, "the full path is shown below the card"
        win.destroy()

    def test_a_very_long_filename_is_shown_untruncated(self, make_launcher,
                                                       dialogs, tmp_path):
        name = "quarterly-" + "x" * 170 + ".qcx"
        qcx = _fake_qcx(tmp_path / name, {"mode": "single", "version": 1})
        dialogs["picked"] = qcx
        app = make_launcher()
        app._inspect_file()
        win = _inspect_window(app)
        texts = _widget_texts(win)
        assert name in texts, "the File row must carry the whole name"
        assert win.title().endswith(name)
        win.destroy()

    def test_close_dismisses_the_window(self, make_launcher, dialogs, tmp_path):
        qcx = _fake_qcx(tmp_path / "c.qcx", {"mode": "single", "version": 1})
        dialogs["picked"] = qcx
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        app._inspect_file()
        win = _ready(_inspect_window(app))
        _press(_button(win, "Close"))
        assert not win.winfo_exists()

    def test_escape_dismisses_the_window(self, make_launcher, dialogs, tmp_path):
        qcx = _fake_qcx(tmp_path / "e.qcx", {"mode": "single", "version": 1})
        dialogs["picked"] = qcx
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        app._inspect_file()
        win = _ready(_inspect_window(app))
        _take_focus(win)
        win.event_generate("<Escape>", when="now")
        win.update()
        assert not win.winfo_exists()

    def test_decrypt_this_file_closes_inspect_and_opens_the_decryptor(
            self, make_launcher, wizards, dialogs, tmp_path):
        qcx = _fake_qcx(tmp_path / "go.qcx", {"mode": "single", "version": 1})
        dialogs["picked"] = qcx
        app = make_launcher(withdraw=False)
        _show_offscreen(app)
        app._inspect_file()
        win = _ready(_inspect_window(app))
        _press(_button(win, "Decrypt this file"))
        assert not win.winfo_exists()
        assert [c["qcx_path"] for c in wizards["decrypt"]] == [qcx]


# ══ updater.py ════════════════════════════════════════════════════════════════


class _FakeResponse:
    def __init__(self, body):
        self._body = body
        self.asked = []          # the byte bounds each read() was given

    def read(self, n=-1):
        self.asked.append(n)
        return self._body if n is None or n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _RecordingParent:
    """Stands in for the launcher window: records what the worker schedules.
    ``fire()`` runs it, the way the Tk loop would; ``exists`` is what
    ``safe_after`` asks before letting the hop through."""

    def __init__(self, fail=False):
        self.calls = []
        self.attempts = 0
        self.exists = True
        self._fail = fail

    def after(self, delay, fn, *args):
        self.attempts += 1
        if self._fail:
            raise tk.TclError("application has been destroyed")
        self.calls.append((delay, fn, args))

    def winfo_exists(self):
        return self.exists

    def fire(self):
        for _delay, fn, args in self.calls:
            fn(*args)


class _SyncThread:
    """Runs the worker inline so a test can see both its effects and any
    exception it fails to swallow (in production those die unseen)."""

    def __init__(self, target=None, daemon=None, **_kw):
        self._target = target
        self.daemon = daemon

    def start(self):
        self._target()


@pytest.fixture
def sync_worker(monkeypatch):
    # Replace the *reference* the updater holds, not ``threading.Thread``
    # itself — patching the stdlib attribute would hand a synchronous shim to
    # every other thread the interpreter starts while the test runs.
    monkeypatch.setattr(updater, "threading", SimpleNamespace(Thread=_SyncThread))


@pytest.fixture
def prefs_only(tmp_path, monkeypatch):
    from quantacrypt.ui.shared import AppPrefs
    monkeypatch.setattr(AppPrefs, "_PATH", str(tmp_path / "prefs.json"))
    return AppPrefs


@pytest.fixture
def shown(monkeypatch):
    """What ``_show_banner`` was asked to render, once the scheduled hop runs."""
    calls = []
    monkeypatch.setattr(updater, "_show_banner",
                        lambda *args: calls.append(args))
    return calls


class TestParseVersion:
    """Release tags are compared as tuples; the parser must be total — any
    string at all has to yield something comparable, never an exception."""

    @pytest.mark.parametrize("tag,expected", [
        ("v1.2.3", (1, 2, 3)),
        ("1.2.3", (1, 2, 3)),
        ("V2.0", (2, 0)),
        ("1.2.3-beta", (1, 2, 3)),
        ("v1.0.0-rc1", (1, 0, 0)),
        ("v3", (3,)),
        ("1.2.3.4.5", (1, 2, 3, 4, 5)),
        ("v10.20.30", (10, 20, 30)),
    ])
    def test_well_formed_tags(self, tag, expected):
        assert updater._parse_version(tag) == expected

    @pytest.mark.parametrize("tag", ["", "-", "abc", "x.1", "v", ".", "..",
                                     "vvv", "v-1.2"])
    def test_unparseable_tags_collapse_to_zero(self, tag):
        assert updater._parse_version(tag) == (0,)

    @pytest.mark.parametrize("tag,expected", [
        ("1.2.x", (1, 2)),      # parsing stops at the first non-numeric part
        ("1..2", (1,)),
        # Run 17: the leading numeric release is what counts, so a PEP 440
        # suffix glued to the last component no longer drops that component
        # ("1.5.0b0" used to read as (1, 5) and every stable 1.5.x looked newer).
        ("1.2.3dev", (1, 2, 3)),
        ("1.5.0b0", (1, 5, 0)),
    ])
    def test_parsing_stops_at_the_first_bad_component(self, tag, expected):
        assert updater._parse_version(tag) == expected

    def test_ordering_is_numeric_not_lexicographic(self):
        assert updater._parse_version("v1.10.0") > updater._parse_version("v1.9.0")
        assert updater._parse_version("v1.3") < updater._parse_version("v1.3.1")
        assert updater._parse_version("v1.3.0") == updater._parse_version("1.3.0")

    def test_a_long_numeric_tag_is_still_parsed(self):
        assert updater._parse_version("v" + ".".join(["9"] * 40)) == (9,) * 40


class TestFetchLatest:
    """The check must be short, identified, and silent on every failure."""

    def test_a_successful_query_returns_the_parsed_release(self, monkeypatch):
        seen = {}
        payload = {"tag_name": "v9.9.9", "html_url": "https://example.test/r"}

        def _urlopen(req, timeout=None):
            seen["url"] = req.full_url
            seen["headers"] = {k.lower(): v for k, v in req.header_items()}
            seen["timeout"] = timeout
            return _FakeResponse(json.dumps(payload).encode())

        monkeypatch.setattr(updater.urllib.request, "urlopen", _urlopen)
        assert updater._fetch_latest() == payload
        assert seen["url"] == updater._API_URL
        assert seen["headers"]["accept"] == "application/vnd.github+json"
        assert seen["headers"]["user-agent"] == "QuantaCrypt-UpdateCheck"
        # A launch must never stall on a slow network.
        assert seen["timeout"] == updater._TIMEOUT == 5

    def test_the_body_read_is_bounded(self, monkeypatch):
        """A release document is a few KB; a daemon thread must not buffer
        whatever a compromised endpoint decides to send."""
        resp = _FakeResponse(json.dumps({"tag_name": "v9.9.9"}).encode())
        monkeypatch.setattr(updater.urllib.request, "urlopen",
                            lambda req, timeout=None: resp)
        assert updater._fetch_latest() == {"tag_name": "v9.9.9"}
        assert resp.asked == [updater._MAX_BODY]
        assert updater._MAX_BODY <= 1 << 20

    def test_a_body_past_the_bound_is_not_a_release(self, monkeypatch):
        big = b'{"tag_name": "v9.9.9", "body": "' + b"x" * (2 << 20) + b'"}'
        monkeypatch.setattr(updater.urllib.request, "urlopen",
                            lambda req, timeout=None: _FakeResponse(big))
        assert updater._fetch_latest() is None, "truncated JSON fails closed"

    def test_a_network_error_is_swallowed(self, monkeypatch):
        def _urlopen(req, timeout=None):
            raise urllib.error.URLError("offline")

        monkeypatch.setattr(updater.urllib.request, "urlopen", _urlopen)
        assert updater._fetch_latest() is None

    def test_a_non_json_body_is_swallowed(self, monkeypatch):
        monkeypatch.setattr(updater.urllib.request, "urlopen",
                            lambda req, timeout=None: _FakeResponse(b"<html>502"))
        assert updater._fetch_latest() is None

    def test_an_empty_body_is_swallowed(self, monkeypatch):
        monkeypatch.setattr(updater.urllib.request, "urlopen",
                            lambda req, timeout=None: _FakeResponse(b""))
        assert updater._fetch_latest() is None


class TestCheckForUpdate:
    """The worker decides whether a banner is worth showing, and schedules it on
    the Tk thread.  Nothing about it may reach the user on a failure."""

    def _run(self, monkeypatch, data, current="1.3.0", parent=None):
        monkeypatch.setattr(updater, "_fetch_latest", lambda: data)
        parent = parent if parent is not None else _RecordingParent()
        updater.check_for_update(parent, current)
        return parent

    def test_a_newer_release_schedules_the_banner(self, monkeypatch, sync_worker,
                                                  prefs_only, shown):
        parent = self._run(monkeypatch, {"tag_name": "v1.9.0",
                                         "html_url": "https://x.test/rel"})
        (delay, _fn, _args), = parent.calls
        assert delay == 0
        parent.fire()
        assert shown == [(parent, "1.9.0", "1.3.0", "v1.9.0", "https://x.test/rel")]

    @pytest.mark.parametrize("current,tag,banner", [
        ("1.5.0b0", "v1.5.0", True),        # run 18 F-001: the final is the update a beta waits for
        ("1.5.0b0", "v1.5.0-beta", False),  # its own tag
        ("1.5.0", "v1.5.0-beta", False),    # the final never offers its beta
        ("1.5.0", "v1.5.2b0", True),        # a newer beta is still newer
        ("1.5.0", "v1.5.0", False),
    ])
    def test_pre_release_rank(self, monkeypatch, sync_worker, prefs_only, shown,
                              current, tag, banner):
        parent = self._run(monkeypatch, {"tag_name": tag, "html_url": "u"}, current=current)
        assert bool(parent.calls) is banner

    def test_a_launcher_closed_before_the_hop_fires_gets_no_banner(
            self, monkeypatch, sync_worker, prefs_only, shown):
        """The window can go between the worker scheduling the banner and
        the Tk loop running it; the hop is skipped, not raised into stderr."""
        parent = self._run(monkeypatch, {"tag_name": "v1.9.0", "html_url": "u"})
        assert len(parent.calls) == 1
        parent.exists = False
        parent.fire()
        assert shown == []

    def test_an_absurdly_long_tag_is_refused(self, monkeypatch, sync_worker,
                                             prefs_only):
        """The version parse only needs the leading digits, so a megabyte
        tag would pass it and land in a label and in prefs.json."""
        parent = self._run(monkeypatch, {"tag_name": "v9.9.9-" + "x" * 100,
                                         "html_url": "u"})
        assert parent.calls == []

    def test_a_tag_at_the_length_limit_is_still_shown(self, monkeypatch,
                                                      sync_worker, prefs_only):
        tag = "v9.9.9-" + "x" * (updater._MAX_TAG - len("v9.9.9-"))
        assert len(tag) == updater._MAX_TAG
        parent = self._run(monkeypatch, {"tag_name": tag, "html_url": "u"})
        assert len(parent.calls) == 1

    def test_the_same_version_schedules_nothing(self, monkeypatch, sync_worker,
                                                prefs_only):
        parent = self._run(monkeypatch, {"tag_name": "v1.3.0", "html_url": "u"})
        assert parent.calls == []

    def test_an_older_release_schedules_nothing(self, monkeypatch, sync_worker,
                                                prefs_only):
        parent = self._run(monkeypatch, {"tag_name": "v1.2.9", "html_url": "u"})
        assert parent.calls == []

    def test_one_patch_release_ahead_is_enough(self, monkeypatch, sync_worker,
                                               prefs_only):
        """Boundary either side of "already up to date"."""
        parent = self._run(monkeypatch, {"tag_name": "v1.3.1", "html_url": "u"})
        assert len(parent.calls) == 1

    def test_a_failed_fetch_schedules_nothing(self, monkeypatch, sync_worker,
                                              prefs_only):
        assert self._run(monkeypatch, None).calls == []

    def test_an_empty_release_document_schedules_nothing(self, monkeypatch,
                                                         sync_worker, prefs_only):
        assert self._run(monkeypatch, {}).calls == []

    def test_a_release_without_a_tag_schedules_nothing(self, monkeypatch,
                                                       sync_worker, prefs_only):
        parent = self._run(monkeypatch, {"tag_name": "", "html_url": "u"})
        assert parent.calls == []

    def test_a_dismissed_release_does_not_come_back(self, monkeypatch,
                                                    sync_worker, prefs_only):
        prefs_only.set("dismissed_update", "v1.9.0")
        parent = self._run(monkeypatch, {"tag_name": "v1.9.0", "html_url": "u"})
        assert parent.calls == []

    def test_dismissing_one_release_does_not_hide_the_next(self, monkeypatch,
                                                           sync_worker,
                                                           prefs_only):
        prefs_only.set("dismissed_update", "v1.4.0")
        parent = self._run(monkeypatch, {"tag_name": "v1.9.0", "html_url": "u"})
        assert len(parent.calls) == 1

    def test_a_destroyed_window_is_not_an_error(self, monkeypatch, sync_worker,
                                                prefs_only):
        """The user may close the launcher mid-check; the worker must absorb
        the TclError rather than raising on a background thread.

        Returning normally *is* the contract here, so the shape of the test is
        "the worker reached the scheduling call, that call blew up, and
        ``check_for_update`` still came back": ``sync_worker`` runs the worker
        inline, so an unswallowed TclError would fail this test outright."""
        parent = self._run(monkeypatch, {"tag_name": "v1.9.0", "html_url": "u"},
                           parent=_RecordingParent(fail=True))
        assert parent.attempts == 1, "the banner was worth scheduling"
        assert parent.calls == []

    def test_a_missing_html_url_still_schedules_with_an_empty_link(
            self, monkeypatch, sync_worker, prefs_only, shown):
        parent = self._run(monkeypatch, {"tag_name": "v2.0.0"})
        parent.fire()
        assert shown[0][-1] == ""

    def test_a_v_prefix_is_stripped_from_both_versions(self, monkeypatch,
                                                       sync_worker, prefs_only,
                                                       shown):
        parent = self._run(monkeypatch, {"tag_name": "v2.0.0", "html_url": "u"},
                           current="v1.3.0")
        parent.fire()
        assert shown[0][1:3] == ("2.0.0", "1.3.0")

    def test_a_non_string_tag_is_absorbed(self, monkeypatch, sync_worker,
                                          prefs_only):
        """GitHub's schema says tag_name is a string, but a proxy or an error
        document can put anything there; the version parse must not escape."""
        parent = self._run(monkeypatch, {"tag_name": 42, "html_url": "u"})
        assert parent.calls == []

    def test_a_non_string_current_version_is_absorbed(self, monkeypatch,
                                                      sync_worker, prefs_only):
        parent = self._run(monkeypatch, {"tag_name": "v9.0.0", "html_url": "u"},
                           current=None)
        assert parent.calls == []

    def test_a_non_dict_release_document_is_ignored(self, monkeypatch,
                                                    sync_worker, prefs_only):
        """`_fetch_latest` returns whatever the JSON parsed to; a top-level
        array (or a captive-portal page that happens to parse) used to reach
        `data.get` and die unseen on the daemon thread (run 13 F-036)."""
        parent = self._run(monkeypatch, ["not", "a", "dict"])
        assert parent.calls == []

    def test_the_check_runs_off_the_main_thread_as_a_daemon(self, monkeypatch,
                                                            prefs_only):
        """A non-daemon thread would hold the interpreter open at quit, and a
        synchronous check would freeze the launcher for the HTTP timeout."""
        started, release = threading.Event(), threading.Event()

        def _slow_fetch():
            started.set()
            release.wait(5)
            return None

        created = []
        real_thread = threading.Thread

        def _spawn(**kw):
            created.append(real_thread(**kw))
            return created[-1]

        monkeypatch.setattr(updater, "_fetch_latest", _slow_fetch)
        monkeypatch.setattr(updater, "threading", SimpleNamespace(Thread=_spawn))
        try:
            updater.check_for_update(_RecordingParent(), "1.3.0")
            # check_for_update has already returned while the fetch is in flight.
            assert started.wait(3), "the worker never ran"
            assert created[0].is_alive()
            assert created[0].daemon is True
        finally:
            release.set()
            created[0].join(5)
        assert not created[0].is_alive()


class TestUpdateBanner:
    """The banner is the only UI the updater owns: where it lands, what it says,
    and what its two buttons do."""

    def test_it_lands_in_the_launcher_banner_slot(self, make_launcher):
        app = make_launcher()
        updater._show_banner(app, "1.9.0", "1.3.0", "v1.9.0", "https://x.test/r")
        banner, = app._banner_slot.winfo_children()
        assert "Update available: v1.9.0 (you have v1.3.0)" in _widget_texts(banner)

    def test_dismissing_remembers_the_tag_and_removes_the_banner(
            self, make_launcher, prefs_dir):
        from quantacrypt.ui.shared import AppPrefs, ICON
        app = make_launcher(withdraw=False)
        updater._show_banner(app, "1.9.0", "1.3.0", "v1.9.0", "https://x.test/r")
        _show_offscreen(app)
        banner, = app._banner_slot.winfo_children()
        _press(_button(banner, ICON["close"]))
        assert AppPrefs.get("dismissed_update") == "v1.9.0"
        assert app._banner_slot.winfo_children() == []

    def test_see_whats_new_opens_the_release_page(self, make_launcher,
                                                  monkeypatch):
        opened = []
        monkeypatch.setattr(updater.webbrowser, "open", opened.append)
        app = make_launcher(withdraw=False)
        url = "https://github.com/alexboccard/QuantaCrypt/releases/tag/v1.9.0"
        updater._show_banner(app, "1.9.0", "1.3.0", "v1.9.0", url)
        _show_offscreen(app)
        banner, = app._banner_slot.winfo_children()
        _press(_button(banner, "See what's new"))
        assert opened == [url]

    @pytest.mark.parametrize("url", [
        "https://x.test/r",
        "http://github.com/alexboccard/QuantaCrypt/releases",        # not TLS
        "https://github.com/alexboccard/QuantaCrypt-evil/releases",  # sibling repo
        "https://github.com/someone-else/QuantaCrypt/releases",
        "javascript:alert(1)",
        "", None, 42,
    ])
    def test_a_link_that_is_not_this_project_on_github_opens_the_releases_page(
            self, make_launcher, monkeypatch, url):
        """``html_url`` is whatever the connection delivered; the only page
        the button may ever open is one under this repository."""
        opened = []
        monkeypatch.setattr(updater.webbrowser, "open", opened.append)
        app = make_launcher(withdraw=False)
        updater._show_banner(app, "1.9.0", "1.3.0", "v1.9.0", url)
        _show_offscreen(app)
        banner, = app._banner_slot.winfo_children()
        _press(_button(banner, "See what's new"))
        assert opened == ["https://github.com/alexboccard/QuantaCrypt/releases"]

    def test_without_a_slot_it_packs_after_the_second_child(self, tk_root):
        """The fallback keeps the banner below the title block rather than
        letting it land on top of the window's heading."""
        parent = tk.Toplevel(tk_root)
        parent.withdraw()
        for _ in range(3):
            tk.Frame(parent, height=4).pack()
        before = parent.pack_slaves()
        updater._show_banner(parent, "2.0.0", "1.0.0", "v2.0.0", "u")
        after = parent.pack_slaves()
        assert len(after) == 4
        assert after[:2] == before[:2]
        assert after[2] not in before, "the banner sits third, after the header"
        assert "Update available: v2.0.0 (you have v1.0.0)" in \
            _widget_texts(after[2])
        assert after[3] is before[2], "the tail is pushed down, not replaced"
        parent.destroy()

    def test_with_one_child_it_packs_last(self, tk_root):
        parent = tk.Toplevel(tk_root)
        parent.withdraw()
        only = tk.Frame(parent, height=4)
        only.pack()
        updater._show_banner(parent, "2.0.0", "1.0.0", "v2.0.0", "u")
        slaves = parent.pack_slaves()
        assert len(slaves) == 2 and slaves[0] is only
        assert "Update available: v2.0.0 (you have v1.0.0)" in \
            _widget_texts(slaves[1])
        parent.destroy()

    def test_with_no_children_it_packs_first(self, tk_root):
        parent = tk.Toplevel(tk_root)
        parent.withdraw()
        updater._show_banner(parent, "2.0.0", "1.0.0", "v2.0.0", "u")
        banner, = parent.pack_slaves()
        assert "Update available" in " ".join(_widget_texts(banner))
        parent.destroy()
