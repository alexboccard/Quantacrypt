"""Behavioural tests for the encryption wizard — ``quantacrypt.ui.encryptor``.

The wizard is the screen that turns a file the user cares about into a .qcx
plus (in split mode) the only copies of the key material.  Every test here
drives real widgets, real threads and real crypto, and asserts on what the
user would see or what landed on disk.  Nothing asserts on the source text of
a method, and nothing asserts "a mock was called" where the effect itself is
observable.

Layout mirrors the module: free functions first, then ``ShareCard``, then the
wizard grouped by the flow it belongs to (source → protection → secret →
output → encrypt → shares).
"""

import gc
import hashlib
import os
import re
import subprocess
import sys
import threading
import time
import types

import pytest

from quantacrypt.ui.shared import MOD as _MOD

import tkinter as tk

from quantacrypt.core import crypto as cc
from quantacrypt.core import package as pkg
from tests.conftest import _widget_texts, requires_tkinter

import quantacrypt.ui.encryptor as enc
from quantacrypt.ui.encryptor import (
    STAGES, STAGE_ARGON, STAGE_COMPRESS, STAGE_ENCKEY, STAGE_KEM,
    STAGE_PAYLOAD, STAGE_WRITE, EncryptorApp, ShareCard,
    _find_stage, _mnemonics_for, _reveal, _root_of, _share_file_names,
    _stage_label,
)

PW = "correct-horse-battery-9"   # comfortably above the 8-char core floor


# ── Harness ──────────────────────────────────────────────────────────────────

def _pump_until(widget, predicate, timeout=30.0):
    """Run the real Tk event loop until ``predicate`` holds (or time runs out).

    ``update()`` is not enough: Tkinter refuses an ``after`` call made from a
    worker thread unless the main thread is actually inside ``mainloop`` — and
    every result the wizard's workers produce comes back exactly that way.
    """
    if predicate():
        return True
    root = _root_of(widget)
    deadline = time.monotonic() + timeout
    result = {"ok": False}

    def poll():
        try:
            if predicate():
                result["ok"] = True
                root.quit()
                return
            if time.monotonic() >= deadline:
                root.quit()
                return
            root.after(10, poll)
        except tk.TclError:
            root.quit()

    root.after(10, poll)
    root.mainloop()
    return result["ok"]


def _packed(widget):
    """True when a widget is currently managed by its parent.

    ``winfo_ismapped`` is useless here: every test window is withdrawn, so
    nothing below it is ever mapped.  What the wizard actually changes is
    whether a section is packed at all.
    """
    return bool(widget.winfo_manager())


def _alive(w):
    try:
        return bool(w.winfo_exists())
    except tk.TclError:
        return False


def _clipboard_empty(root):
    """True when nothing is on the system clipboard.  On macOS the wipe is
    made outside Tk (NSPasteboard), so it is read back outside Tk too."""
    if sys.platform == "darwin":
        r = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=5)
        return r.stdout == ""
    try:
        root.clipboard_get()
    except tk.TclError:
        return True
    return False


def _menu_labels(menu):
    end = menu.index("end")
    if end is None:
        return []
    return ["--" if menu.type(i) == "separator" else menu.entrycget(i, "label")
            for i in range(end + 1)]


def _press(app, sequence, widget=None, **kw):
    """Deliver a real key event to the wizard.

    Tk routes key events to the focused window, and a withdrawn window can
    take neither focus nor keys — so the window is shown for the keystroke and
    parked again afterwards.

    "Focused" has to mean focused HERE.  ``event_generate`` does not deliver a
    key to the widget it is called on: Tk hands it to the application's focus
    widget, and the bindings that then run are that widget's bindtags.  So a
    focus left behind by an earlier test — on the shared root, or on a
    dropdown that has since gone — silently sends the keystroke somewhere
    whose bindtags do not include this window, and the shortcut under test
    never runs.  ``focus_get() is not None`` cannot see that: it is true
    whenever ANY window in the process has the focus.  Waiting for the focus
    to land inside this window is what makes the delivery deterministic.
    """
    app.deiconify()
    app.update()
    target = widget if widget is not None else app
    prefix = str(app) if str(app).endswith(".") else str(app) + "."

    def _focused_here():
        try:
            focused = app.focus_get()
        except (KeyError, tk.TclError):
            return False        # focus is in a window this interpreter lost
        if focused is None:
            return False
        name = str(focused)
        return name == str(target) or name.startswith(prefix)

    for _ in range(3):
        target.focus_force()
        deadline = time.monotonic() + 2
        while not _focused_here() and time.monotonic() < deadline:
            app.update()
            time.sleep(0.01)
        if _focused_here():
            break
    else:
        app.withdraw()
        pytest.skip("the window manager would not give the test window focus")
    if widget is not None:
        widget.focus_set()
        app.update()
    target.event_generate(sequence, when="now", **kw)
    try:
        app.update()
        app.withdraw()          # the keystroke may have closed the window
        app.update()
    except tk.TclError:
        pass


class _Confirms:
    """Stand-in for the themed ``confirm`` dialog: records what the wizard
    asked and answers it.  ``answer`` may be a bool or a callable taking the
    dialog title, so a single test can accept one prompt and refuse another."""

    def __init__(self, answer=True):
        self.calls = []
        self.answer = answer

    def __call__(self, parent, title, message, **kw):
        self.calls.append((title, message))
        return self.answer(title) if callable(self.answer) else self.answer

    @property
    def titles(self):
        return [t for t, _ in self.calls]

    def message_for(self, title):
        return next(m for t, m in self.calls if t == title)


class _Boxes:
    """Stand-in for ``tkinter.messagebox`` (askyesno / showerror)."""

    def __init__(self, yes=True):
        self.asked = []
        self.errors = []
        self.yes = yes

    def askyesno(self, title, message, **kw):
        self.asked.append((title, message))
        return self.yes

    def showerror(self, title, message, **kw):
        self.errors.append((title, message))


class _Dialogs:
    """Stand-in for ``tkinter.filedialog``; every answer is programmable."""

    def __init__(self, directory="", savename="", openfiles=()):
        self.directory = directory
        self.savename = savename
        self.openfiles = openfiles
        self.calls = []

    def askdirectory(self, **kw):
        self.calls.append(("askdirectory", kw))
        return self.directory

    def asksaveasfilename(self, **kw):
        self.calls.append(("asksaveasfilename", kw))
        return self.savename

    def askopenfilenames(self, **kw):
        self.calls.append(("askopenfilenames", kw))
        return self.openfiles


@pytest.fixture(autouse=True)
def _no_worker_or_interpreter_outlives_its_test():
    """Keep two things from crossing a test boundary: a wizard worker thread,
    and a dead-but-uncollected Tk interpreter.

    Every run reports progress from a worker thread through ``after()``
    (``shared.safe_after``), and CPython services a cyclic-GC pass on
    whichever thread happens to trip the allocation counter.  A Tk root that
    died in an earlier test but is still held by a reference cycle is then
    finalised on THAT thread — ``Tcl_DeleteInterp`` off the main thread — and
    Tcl aborts the whole process with

        Tcl_AsyncDelete: async handler deleted by the wrong thread

    which pytest can only report as "whatever test was running when we died"
    — under xdist, as a failure in an unrelated test.  It bit this file on
    ``--randomly-seed=1``, 54 tests in, and reproduces outside pytest too:
    destroy six roots that a reference cycle still owns, start one thread
    that allocates and calls ``after()``, and it aborts every time; add a
    ``gc.collect()`` after each root and it survives every time.

    Autouse, so pytest builds this first and finalises it last — after
    ``tk_root`` has destroyed and dropped its root (verified: an autouse
    fixture's teardown runs after that of the fixtures the test requested).
    The collect BEFORE the test is deliberately redundant with that: it is
    what makes the guarantee independent of finalisation order, and it is
    what this test's own workers rely on.  The join is the other half of the
    same leak — a worker started by one test has no business still running
    inside the next one.
    """
    gc.collect()                      # no earlier test's interpreter is left
    before = set(threading.enumerate())
    yield
    # Generous: mkapp arms Cancel before it destroys a window, so a worker
    # stops at the next chunk boundary and these joins normally cost nothing.
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        strays = [t for t in threading.enumerate()
                  if t not in before and t.is_alive()]
        if not strays:
            break
        for t in strays:
            t.join(0.05)
    gc.collect()


@pytest.fixture
def mkapp(tk_root, monkeypatch):
    """Factory for a real, off-screen EncryptorApp with OS side-effects muted.

    Everything the wizard reaches out to (notifications, the embedded-decryptor
    probe) is stubbed; dialogs are left to the individual test so the default
    is "a dialog would block", not "a dialog was silently answered".
    """
    monkeypatch.setattr(enc, "notify", lambda *a, **k: None)
    made = []

    def factory(*, find_dec=None, on_close=None, center_at=None, dnd=None):
        monkeypatch.setattr(EncryptorApp, "_find_dec", lambda self: find_dec)
        if dnd is not None:
            monkeypatch.setattr(enc, "_DND_FILES", "DND_Files")
            monkeypatch.setattr(EncryptorApp, "drop_target_register",
                                lambda self, *a: dnd(), raising=False)
            monkeypatch.setattr(EncryptorApp, "dnd_bind",
                                lambda self, *a: None, raising=False)
        app = EncryptorApp(tk_root, on_close=on_close, center_at=center_at)
        app.withdraw()
        app.update()
        made.append(app)
        return app

    yield factory
    for app in made:
        # Arm Cancel before the window goes: a run left going at the end of a
        # test would otherwise encrypt on into the next one.
        try:
            app._cancel_event.set()
        except Exception:
            pass
        try:
            app.destroy()
        except tk.TclError:
            pass


@pytest.fixture(scope="module")
def shamir_shares(tmp_path_factory):
    """One real 2-of-3 split run, reused wherever share codes are needed."""
    d = tmp_path_factory.mktemp("shamir")
    src = d / "secret.bin"
    src.write_bytes(b"split me" * 32)
    out = str(d / "secret.qcx")
    res = pkg.encrypt_to_qcx(str(src), out, mode="shamir", k=2, n=3)
    return out, [s["code"] for s in res["shares"]], [s["mnemonic"] for s in res["shares"]]


def _fill_single(app, src, out, password=PW):
    """Drive the form the way a user would for a single-file password run."""
    app._on_file(str(src))
    app._out.delete(0, "end")
    app._out.insert(0, str(out))
    app._pw1v.set(password)
    app._pw2v.set(password)
    app.update()


# ─────────────────────────────────────────────────────────────────────────────
# Free functions
# ─────────────────────────────────────────────────────────────────────────────

class TestFindStage:
    """Contract: raw core progress strings map to ONE semantic stage, most
    specific keyword first, and anything unrecognised maps to nothing."""

    @pytest.mark.parametrize("msg, expected", [
        ("Compressing folder... 40%", STAGE_COMPRESS),
        ("Deriving Argon2 key...", STAGE_ARGON),
        ("Generating Kyber keypair...", STAGE_KEM),
        ("Encapsulating shared secret...", STAGE_KEM),
        ("Deriving master key...", STAGE_KEM),
        ("Encrypting payload... 12%", STAGE_PAYLOAD),
        ("Writing binary... 100%", STAGE_WRITE),
    ])
    def test_each_core_message_lands_on_its_stage(self, msg, expected):
        assert _find_stage(msg) == expected

    def test_private_key_wins_over_the_master_key_keyword(self):
        # "Encrypting Kyber private key under master key" contains BOTH
        # "private key" and "master key"; the bar must not jump backwards.
        assert _find_stage("Encrypting Kyber private key under master key") == STAGE_ENCKEY

    def test_matching_is_case_insensitive(self):
        assert _find_stage("DERIVING ARGON2 KEY") == STAGE_ARGON

    @pytest.mark.parametrize("msg", [None, "", "   ", "some unrelated chatter"])
    def test_unknown_messages_map_to_nothing(self, msg):
        assert _find_stage(msg) is None


class TestStageLabel:
    """Contract: the user sees the friendly stage name plus any percentage the
    core reported — never the raw core string."""

    def test_percentage_is_carried_over(self):
        assert _stage_label(STAGE_PAYLOAD, "Encrypting payload... 45%") == "Encrypting file  45%"

    def test_zero_percent_is_still_shown(self):
        # 0 is falsy in a lot of code; the match object is what decides here.
        assert _stage_label(STAGE_WRITE, "Writing binary... 0%") == "Saving  0%"

    def test_message_without_a_percentage_gives_the_bare_label(self):
        assert _stage_label(STAGE_KEM, "Generating Kyber keypair") == "Generating protection"

    def test_no_message_at_all_gives_the_bare_label(self):
        assert _stage_label(STAGE_COMPRESS) == STAGES[STAGE_COMPRESS][0]

    def test_raw_core_wording_never_reaches_the_label(self):
        label = _stage_label(STAGE_ARGON, "Deriving Argon2 key... 30%")
        assert "argon" not in label.lower() and label == "Securing password  30%"


class TestReveal:
    """Contract: ``_reveal`` launches the platform handler and reports whether
    it managed to; callers turn False into a status line."""

    @pytest.fixture
    def popen_calls(self, monkeypatch):
        calls = []
        monkeypatch.setattr(enc.subprocess, "Popen", lambda argv, **kw: calls.append(argv))
        return calls

    def test_reveal_delegates_to_the_shared_file_manager_helper(self, monkeypatch):
        seen = []
        monkeypatch.setattr(enc, "reveal_path", lambda p: seen.append(p) or True)
        assert _reveal("/tmp/a b.qcx") is True
        assert seen == ["/tmp/a b.qcx"]

    def test_reveal_reports_the_helper_failing(self, monkeypatch):
        monkeypatch.setattr(enc, "reveal_path", lambda p: False)
        assert _reveal("/tmp/a.qcx") is False

    def test_open_file_uses_open_on_macos(self, popen_calls, monkeypatch):
        monkeypatch.setattr(enc.sys, "platform", "darwin")
        assert _reveal("/tmp/a b.qcx", open_file=True) is True
        assert popen_calls == [["open", "--", "/tmp/a b.qcx"]]

    def test_open_file_keeps_a_dashed_name_out_of_opens_flags(self, popen_calls,
                                                              monkeypatch):
        """The Output field is free text: -foo.qcx is a file, not options."""
        monkeypatch.setattr(enc.sys, "platform", "darwin")
        assert _reveal("-foo.qcx", open_file=True) is True
        assert popen_calls == [["open", "--", "-foo.qcx"]]

    def test_open_file_uses_xdg_open_elsewhere(self, popen_calls, monkeypatch):
        monkeypatch.setattr(enc.sys, "platform", "linux")
        assert _reveal("/tmp/a.qcx", open_file=True) is True
        assert popen_calls == [["xdg-open", "/tmp/a.qcx"]]

    def test_open_file_absolutises_the_path_for_xdg_open(self, popen_calls,
                                                         monkeypatch, tmp_path):
        """xdg-open has no ``--``; an absolute path can never read as a flag."""
        monkeypatch.setattr(enc.sys, "platform", "linux")
        monkeypatch.chdir(tmp_path)
        assert _reveal("-foo.qcx", open_file=True) is True
        assert popen_calls == [["xdg-open", str(tmp_path / "-foo.qcx")]]

    def test_open_file_uses_startfile_on_windows(self, monkeypatch):
        started = []
        monkeypatch.setattr(enc.sys, "platform", "win32")
        monkeypatch.setattr(enc.os, "startfile", started.append, raising=False)
        assert _reveal(r"C:\tmp\a.qcx", open_file=True) is True
        assert started == [r"C:\tmp\a.qcx"]

    def test_a_handler_that_cannot_launch_reports_false(self, monkeypatch):
        monkeypatch.setattr(enc.sys, "platform", "darwin")
        def _boom(*a, **k):
            raise OSError("no such tool")
        monkeypatch.setattr(enc.subprocess, "Popen", _boom)
        assert _reveal("/tmp/a.qcx", open_file=True) is False


class TestMnemonicsFor:
    """Contract: one mnemonic per share, carrying the threshold the core never
    stores in the share code itself."""

    def test_codes_from_the_core_are_used_as_they_came(self, shamir_shares):
        _out, codes, mnemonics = shamir_shares
        assert _mnemonics_for(codes, 2, mnemonics) == mnemonics
        # Recomputing the same codes produces the same words, so comparing
        # against the core's own list proves nothing on its own.  Values the
        # decoder could never invent are what shows the fast path is taken.
        sentinels = ["first phrase", "second phrase", "third phrase"]
        assert _mnemonics_for(codes, 2, sentinels) == sentinels

    def test_a_known_list_longer_than_the_shares_is_recomputed(self, shamir_shares):
        _out, codes, mnemonics = shamir_shares
        got = _mnemonics_for(codes[:2], 2, mnemonics)      # 3 known, 2 shares
        assert len(got) == 2
        for code, phrase in zip(codes[:2], got):
            assert len(phrase.split()) == cc.MNEMONIC_WORDS_PER_SHARE
            assert cc.mnemonic_to_share(phrase)["value"] == cc.decode_share(code)["value"]

    def test_recomputed_mnemonics_carry_the_injected_threshold(self, shamir_shares):
        _out, codes, _mn = shamir_shares
        got = _mnemonics_for(codes, 2)
        assert len(got) == 3
        for code, phrase in zip(codes, got):
            words = phrase.split()
            assert len(words) == cc.MNEMONIC_WORDS_PER_SHARE
            back = cc.mnemonic_to_share(phrase)
            assert back["threshold"] == 2                      # injected, not 0
            assert back["index"] == cc.decode_share(code)["index"]
            assert back["value"] == cc.decode_share(code)["value"]

    def test_a_short_known_list_is_ignored_and_recomputed(self, shamir_shares):
        _out, codes, _mn = shamir_shares
        got = _mnemonics_for(codes, 2, ["only-one"])
        assert got != ["only-one"] and len(got) == 3
        assert all(len(p.split()) == cc.MNEMONIC_WORDS_PER_SHARE for p in got)

    def test_a_known_list_with_a_hole_is_recomputed(self, shamir_shares):
        _out, codes, mnemonics = shamir_shares
        got = _mnemonics_for(codes, 2, [mnemonics[0], None, mnemonics[2]])
        assert None not in got and len(got) == 3
        # Not "the hole was patched" — the WHOLE list is recomputed, so every
        # entry must decode back to its own share.
        for code, phrase in zip(codes, got):
            assert len(phrase.split()) == cc.MNEMONIC_WORDS_PER_SHARE
            back = cc.mnemonic_to_share(phrase)
            assert back["value"] == cc.decode_share(code)["value"]
            assert back["threshold"] == 2

    def test_an_undecodable_share_yields_none_rather_than_raising(self, shamir_shares):
        _out, codes, _mn = shamir_shares
        got = _mnemonics_for([codes[0], "not-a-share"], 2)
        assert got[1] is None and isinstance(got[0], str)

    def test_no_shares_gives_no_mnemonics(self):
        assert _mnemonics_for([], 2) == []


@requires_tkinter
class TestRootOf:
    """Contract: clipboard timers must be owned by something that outlives the
    wizard window, i.e. the root above it."""

    def test_a_widget_in_a_toplevel_resolves_to_the_root(self, tk_root):
        top = tk.Toplevel(tk_root)
        label = tk.Label(top, text="x")
        assert _root_of(label) is tk_root
        top.destroy()

    def test_a_widget_in_the_root_resolves_to_the_root_itself(self, tk_root):
        label = tk.Label(tk_root, text="x")
        assert _root_of(label) is tk_root

    def test_a_widget_that_cannot_answer_is_returned_unchanged(self):
        broken = types.SimpleNamespace()
        def _raise():
            raise tk.TclError("gone")
        broken.winfo_toplevel = _raise
        assert _root_of(broken) is broken


class TestShareFileNames:
    """Contract: one RUN of share files shares one stem, so a recipient can
    match "share-2-of-3" to the rest of their set, and an earlier run's files
    are never overwritten."""

    def test_names_follow_the_share_i_of_n_pattern(self, tmp_path):
        names, renamed = _share_file_names(str(tmp_path), "secret", 3)
        assert [os.path.basename(p) for p in names] == [
            "secret.share-1-of-3.txt", "secret.share-2-of-3.txt", "secret.share-3-of-3.txt"]
        assert renamed is False

    def test_a_single_collision_moves_the_whole_set(self, tmp_path):
        (tmp_path / "secret.share-2-of-3.txt").write_text("someone else's key")
        names, renamed = _share_file_names(str(tmp_path), "secret", 3)
        assert renamed is True
        assert [os.path.basename(p) for p in names] == [
            "secret_2.share-1-of-3.txt", "secret_2.share-2-of-3.txt",
            "secret_2.share-3-of-3.txt"]

    def test_a_dangling_symlink_counts_as_taken(self, tmp_path):
        # open(O_EXCL) fails on a dangling link too, so exists() would loop.
        os.symlink(str(tmp_path / "nowhere"), str(tmp_path / "s.share-1-of-2.txt"))
        names, renamed = _share_file_names(str(tmp_path), "s", 2)
        assert renamed is True
        assert os.path.basename(names[0]) == "s_2.share-1-of-2.txt"

    def test_no_shares_asks_for_no_files(self, tmp_path):
        # Zero-length loop: nothing is claimed, so nothing collides and the
        # first (unsuffixed) stem is reported as free.
        names, renamed = _share_file_names(str(tmp_path), "secret", 0)
        assert names == [] and renamed is False

    def test_a_single_share_still_says_one_of_one(self, tmp_path):
        names, renamed = _share_file_names(str(tmp_path), "secret", 1)
        assert [os.path.basename(p) for p in names] == ["secret.share-1-of-1.txt"]
        assert renamed is False

    def test_a_unicode_stem_with_spaces_and_quotes_is_preserved(self, tmp_path):
        stem = "my 'wíll' \"2030\""
        names, _ = _share_file_names(str(tmp_path), stem, 1)
        assert os.path.basename(names[0]) == f"{stem}.share-1-of-1.txt"
        assert os.path.dirname(names[0]) == str(tmp_path)

    def test_ninety_nine_sets_is_the_end_of_the_road(self, tmp_path):
        import errno
        for suffix in range(1, 100):
            s = "s" if suffix == 1 else f"s_{suffix}"
            (tmp_path / f"{s}.share-1-of-1.txt").write_text("x")
        with pytest.raises(FileExistsError) as ei:
            _share_file_names(str(tmp_path), "s", 1)
        assert ei.value.errno == errno.EEXIST
        assert "choose another folder" in str(ei.value)

    def test_one_free_slot_below_the_cap_still_succeeds(self, tmp_path):
        for suffix in range(1, 99):
            s = "s" if suffix == 1 else f"s_{suffix}"
            (tmp_path / f"{s}.share-1-of-1.txt").write_text("x")
        names, renamed = _share_file_names(str(tmp_path), "s", 1)
        assert renamed is True
        assert os.path.basename(names[0]) == "s_99.share-1-of-1.txt"


# ─────────────────────────────────────────────────────────────────────────────
# ShareCard
# ─────────────────────────────────────────────────────────────────────────────

@requires_tkinter
class TestShareCard:
    """Contract: a card shows ONE share, in words or as a code, and copying it
    starts the clipboard auto-clear countdown."""

    def _card(self, tk_root, shamir_shares, with_mnemonic=True):
        _out, codes, mnemonics = shamir_shares
        card = ShareCard(tk_root, 1, codes[0],
                         mnemonic=mnemonics[0] if with_mnemonic else None)
        card.pack()
        tk_root.update()
        return card, codes[0], mnemonics[0]

    def _shown(self, card):
        return card._txt.get("1.0", "end-1c")

    def test_words_are_shown_first_when_a_mnemonic_exists(self, tk_root, shamir_shares):
        card, code, mnemonic = self._card(tk_root, shamir_shares)
        assert self._shown(card) == mnemonic
        assert card._fmt_btn.cget("text") == "Switch to code"
        assert "Share 1" in _widget_texts(card)

    def test_toggling_swaps_the_format_both_ways(self, tk_root, shamir_shares):
        card, code, mnemonic = self._card(tk_root, shamir_shares)
        card._toggle_fmt()
        assert self._shown(card) == code
        assert card._fmt_btn.cget("text") == "Switch to words"
        card._toggle_fmt()
        assert self._shown(card) == mnemonic

    def test_without_a_mnemonic_the_code_is_shown_and_no_toggle_offered(
            self, tk_root, shamir_shares):
        card, code, _mn = self._card(tk_root, shamir_shares, with_mnemonic=False)
        assert self._shown(card) == code
        assert not hasattr(card, "_fmt_btn")

    def test_the_text_box_grows_to_fit_a_fifty_word_mnemonic(self, tk_root, shamir_shares):
        card, _code, _mn = self._card(tk_root, shamir_shares)
        tk_root.update()
        rows = card._txt.count("1.0", "end", "displaylines")
        rows = int(rows[0] if isinstance(rows, (tuple, list)) else rows)
        # The box is sized to what it actually wraps to, not to a fixed height:
        # a fifty-word phrase needs more than the two rows a code needs.
        assert int(card._txt.cget("height")) == max(2, min(10, rows))
        assert int(card._txt.cget("height")) > 2
        if rows <= 10:
            # "the outer canvas owns the wheel" — nothing may be hidden behind
            # an internal scroll.
            assert card._txt.yview() == (0.0, 1.0)

    def test_an_unmeasurable_text_box_falls_back_to_a_readable_height(
            self, tk_root, shamir_shares):
        card, _code, _mn = self._card(tk_root, shamir_shares)
        def _boom(*a, **k):
            raise tk.TclError("no displaylines on this build")
        card._txt.count = _boom
        card._fit_height()
        assert int(card._txt.cget("height")) == 6   # mnemonic-sized fallback

    def test_copy_puts_the_shown_format_on_the_clipboard(self, tk_root, shamir_shares):
        card, code, mnemonic = self._card(tk_root, shamir_shares)
        card._copy()
        assert tk_root.clipboard_get() == mnemonic
        assert card._copy_btn.cget("text") == "✓ Copied"
        assert "Clipboard clears in" in card._clip_lbl.cget("text")
        card._toggle_fmt()
        card._copy()
        assert tk_root.clipboard_get() == code

    def test_a_clipboard_that_refuses_says_so(self, tk_root, shamir_shares):
        card, _code, _mn = self._card(tk_root, shamir_shares)
        def _boom(*a, **k):
            raise tk.TclError("no clipboard")
        card.clipboard_append = _boom
        card._copy()
        assert card._copy_btn.cget("text") == "⚠ Failed"

    def test_marking_saved_disables_copying_and_blanks_the_countdown_label(
            self, tk_root, shamir_shares):
        card, _code, _mn = self._card(tk_root, shamir_shares)
        card._copy()
        card.mark_saved()
        assert card._copy_btn.cget("text") == "✓ Saved"
        assert card._copy_btn._enabled is False
        assert card._clip_lbl.cget("text") == ""      # label detached, not the wipe
        assert card.cget("highlightbackground") == enc.C["success"]

    def test_saving_keeps_the_clipboard_wipe_armed(self, tk_root, shamir_shares):
        """Copy, then "Save individual files →" seconds later: the share is
        still on the pasteboard, and the 60 s wipe the banner promises has
        to fire for it.  Saving may only take the label away."""
        card, _code, mnemonic = self._card(tk_root, shamir_shares)
        card._copy()
        timer = card._clip_timer
        card.mark_saved()
        assert timer._job is not None, "still counting down"
        assert timer._written == mnemonic, "the copy is still known"
        assert timer._concealed is False or timer._change is not None, \
            "the changeCount witness survives the save"
        timer._remain = 0
        timer._tick()                                  # the countdown runs out
        assert _clipboard_empty(tk_root)
        assert timer._written is None and timer._change is None

    def test_command_c_on_the_share_text_is_a_concealed_timed_copy(
            self, tk_root, shamir_shares):
        """Select-all + ⌘C on the share is the habitual copy gesture; it has
        to arm the same countdown as the button rather than Tk's stock
        append that a clipboard manager keeps for ever."""
        card, _code, mnemonic = self._card(tk_root, shamir_shares)
        tk_root.clipboard_clear()
        card._txt.tag_add("sel", "1.0", "end")
        card._txt.event_generate("<<Copy>>")
        tk_root.update()
        assert tk_root.clipboard_get() == mnemonic
        assert card._clip_timer._written == mnemonic
        assert card._clip_lbl.cget("text").startswith("Clipboard clears in")
        assert card._copy_btn.cget("text") == "✓ Copied"

    def test_the_context_menu_copy_takes_the_same_route(self, tk_root,
                                                        shamir_shares, monkeypatch):
        posted = []
        monkeypatch.setattr(tk.Menu, "tk_popup",
                            lambda self, x, y, entry="": posted.append(self))
        card, _code, mnemonic = self._card(tk_root, shamir_shares)
        card._txt.tag_add("sel", "1.0", "end")
        tk_root.update()
        card._txt.event_generate("<Button-3>", x=3, y=3)
        tk_root.update()
        menu, = posted
        tk_root.clipboard_clear()
        menu.invoke(_menu_labels(menu).index("Copy"))
        tk_root.update()
        assert tk_root.clipboard_get() == mnemonic
        assert card._clip_timer._written == mnemonic
        assert card._clip_lbl.cget("text").startswith("Clipboard clears in")

    def test_marking_a_destroyed_card_is_survivable(self, tk_root, shamir_shares):
        # Contract: mark_saved is fired from a save handler that may outlive
        # the card (the wizard can be rebuilt underneath it); it must no-op.
        card, _code, _mn = self._card(tk_root, shamir_shares)
        card._copy_btn.destroy()
        card.mark_saved()
        assert _alive(card)


# ─────────────────────────────────────────────────────────────────────────────
# Window plumbing
# ─────────────────────────────────────────────────────────────────────────────

@requires_tkinter
class TestWindowSetup:
    """Contract: the window advertises drag & drop only when it registered a
    drop target, and offers a Home button only when there is a launcher."""

    def test_without_tkinterdnd_the_card_promises_only_clicking(self, mkapp):
        app = mkapp()
        assert app._dnd_ok is False
        assert app._file_card._line2.cget("text") == "Click anywhere"

    def test_a_registered_drop_target_is_advertised(self, mkapp):
        app = mkapp(dnd=lambda: None)
        assert app._dnd_ok is True
        assert app._file_card._line2.cget("text") == "Click anywhere · or drag & drop"

    def test_a_failed_registration_is_not_advertised(self, mkapp):
        def _boom():
            raise RuntimeError("root is not a TkinterDnD.Tk")
        app = mkapp(dnd=_boom)
        assert app._dnd_ok is False
        assert app._file_card._line2.cget("text") == "Click anywhere"

    def test_a_launcher_gets_a_home_button(self, mkapp):
        with_home = mkapp(on_close=lambda: None)
        assert "← Home" in _widget_texts(with_home)

    def test_standalone_has_no_home_button(self, mkapp):
        assert "← Home" not in _widget_texts(mkapp())

    def test_center_at_places_the_window_around_the_given_point(self):
        placed = []
        ns = types.SimpleNamespace(
            update_idletasks=lambda: None,
            winfo_width=lambda: 620, winfo_height=lambda: 780,
            winfo_screenwidth=lambda: 1600, winfo_screenheight=lambda: 1200,
            geometry=placed.append)
        EncryptorApp._center(ns, center_at=(800, 600))
        assert placed == ["+490+210"]

    def test_center_clamps_to_the_visible_desktop(self):
        placed = []
        ns = types.SimpleNamespace(
            update_idletasks=lambda: None,
            winfo_width=lambda: 620, winfo_height=lambda: 780,
            winfo_screenwidth=lambda: 1600, winfo_screenheight=lambda: 1200,
            geometry=placed.append)
        EncryptorApp._center(ns, center_at=(10, 10))
        assert placed == ["+0+0"]

    def test_without_a_point_the_window_centers_on_screen(self):
        placed = []
        ns = types.SimpleNamespace(
            update_idletasks=lambda: None,
            winfo_width=lambda: 620, winfo_height=lambda: 780,
            winfo_screenwidth=lambda: 1600, winfo_screenheight=lambda: 1200,
            geometry=placed.append)
        EncryptorApp._center(ns)
        assert placed == ["+490+210"]

    def test_the_wheel_scrolls_the_form(self, mkapp):
        app = mkapp()
        # The handler is deliberately focus-aware (see the next test), so this
        # only exercises anything with the focus inside the wizard.  Left to
        # chance it inherits whatever the window manager last focused, and on
        # a withdrawn wizard that is the shared root — a different toplevel,
        # for which doing nothing is the correct behaviour and the assertion
        # below would fail for the wrong reason.  So claim the focus first.
        app.deiconify()
        app._cv.focus_force()
        app.update()
        focused = app.focus_get()
        assert focused is None or focused.winfo_toplevel() is app
        app._cv.yview_moveto(0.0)
        app.update()
        app.event_generate("<MouseWheel>", delta=-120, when="now")
        app.update()
        assert app._cv.yview()[0] > 0.0
        app.withdraw()

    def test_the_wheel_leaves_the_form_alone_while_a_dropdown_has_focus(self, mkapp):
        # A dropdown lives in its own Toplevel; scrolling there must not move
        # the wizard's canvas underneath it.
        app = mkapp()
        app._cv.yview_moveto(0.0)
        other = tk.Toplevel(app)
        other.geometry("100x100-4000-4000")
        entry = tk.Entry(other)
        entry.pack()
        other.update()
        entry.focus_force()
        app.update()
        if app.focus_get() is not entry:
            other.destroy()
            pytest.skip("window manager would not move focus to the popup")
        app.event_generate("<MouseWheel>", delta=-120, when="now")
        app.update()
        assert app._cv.yview()[0] == 0.0
        other.destroy()


@requires_tkinter
class TestKeyboardShortcuts:
    """Contract: ⌘O opens the right picker for the current source type, ⌘↵
    starts the run, and both say so instead of doing nothing while busy."""

    def test_command_o_opens_the_file_picker(self, mkapp, monkeypatch, tmp_path):
        from tkinter import filedialog as real_fd
        src = tmp_path / "picked.bin"
        src.write_bytes(b"data")
        monkeypatch.setattr(real_fd, "askopenfilename", lambda **kw: str(src))
        app = mkapp()
        _press(app, f"<{_MOD}-o>")
        assert app._path == str(src)
        assert app._out.get().endswith("picked.qcx")

    def test_command_o_in_batch_mode_opens_the_multi_picker(self, mkapp, monkeypatch, tmp_path):
        a, b = tmp_path / "a.bin", tmp_path / "b.bin"
        for p in (a, b):
            p.write_bytes(b"x")
        monkeypatch.setattr(enc, "filedialog", _Dialogs(openfiles=(str(a), str(b))))
        app = mkapp()
        app._src_type.set("batch")
        app.update()
        _press(app, f"<{_MOD}-o>")
        assert app._batch_paths == [str(a), str(b)]

    def test_command_o_while_busy_explains_instead_of_opening(self, mkapp, monkeypatch):
        opened = []
        monkeypatch.setattr(enc, "filedialog", _Dialogs())
        app = mkapp()
        monkeypatch.setattr(app._file_card, "_pick", lambda: opened.append(1))
        app._busy = True
        _press(app, f"<{_MOD}-o>")
        assert opened == []
        assert app._err.cget("text") == "Busy. Please wait for encryption to finish"

    def test_command_return_starts_the_run(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        started = []
        monkeypatch.setattr(app, "_run", lambda p: started.append(p))
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        src = tmp_path / "in.bin"
        src.write_bytes(b"payload" * 8)
        _fill_single(app, src, tmp_path / "out.qcx")
        _press(app, f"<{_MOD}-Return>")
        assert _pump_until(app, lambda: bool(started), 10)
        assert started[0]["path"] == str(src)

    def test_command_return_while_busy_says_so(self, mkapp):
        app = mkapp()
        app._busy = True
        _press(app, f"<{_MOD}-Return>")
        assert app._err.cget("text") == "Busy. Please wait for encryption to finish"


@requires_tkinter
class TestStatusLine:
    """Contract: one label, two voices — grey status, red error — and a flash
    that never wipes a message somebody else wrote after it."""

    def test_status_is_grey_and_error_is_red(self, mkapp):
        app = mkapp()
        app._set_status("scanning")
        assert (app._err.cget("text"), app._err.cget("fg")) == ("scanning", enc.C["text3"])
        app._set_error("nope")
        assert (app._err.cget("text"), app._err.cget("fg")) == ("nope", enc.C["error"])

    def test_a_flash_clears_itself(self, mkapp):
        app = mkapp()
        app._flash_status("temporary", ms=20)
        assert app._err.cget("text") == "temporary"
        assert _pump_until(app, lambda: app._err.cget("text") == "", 5)

    def test_a_flash_never_wipes_a_newer_message(self, mkapp):
        app = mkapp()
        app._flash_status("old", ms=20)
        app._set_error("newer and more important")
        # Let the flash's timer fire: it must find a different message on the
        # label and leave it alone.
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            app.update()
            time.sleep(0.01)
        assert app._err.cget("text") == "newer and more important"
        assert app._err.cget("fg") == enc.C["error"]


# ─────────────────────────────────────────────────────────────────────────────
# Source step
# ─────────────────────────────────────────────────────────────────────────────

@requires_tkinter
class TestSourceTypeSwitching:
    """Contract: the picker, the action button and section 4 all follow the
    Single File / Entire Folder / Multiple Files toggle."""

    def test_file_mode_is_the_default_and_is_restored_by_the_toggle(self, mkapp):
        app = mkapp()
        assert app._btn.cget("text") == "Encrypt File →"
        assert _packed(app._file_card)
        assert _packed(app._out_section)
        # The initial state is also what _build left behind, so prove the
        # toggle really rebuilds it after a round trip through the other modes.
        for other in ("folder", "batch"):
            app._src_type.set(other)
            app.update()
        app._src_type.set("file")
        app.update()
        assert app._btn.cget("text") == "Encrypt File →"
        assert _packed(app._file_card) and _packed(app._out_section)
        assert not _packed(app._batch_frame)

    def test_folder_mode_switches_the_picker_and_the_button(self, mkapp):
        app = mkapp()
        app._src_type.set("folder")
        app.update()
        assert app._file_card._folder_mode is True
        assert app._btn.cget("text") == "Encrypt Folder →"
        assert "Select a folder to encrypt" in _widget_texts(app._file_card)

    def test_batch_mode_hides_the_single_output_row(self, mkapp):
        app = mkapp()
        app._src_type.set("batch")
        app.update()
        assert not _packed(app._file_card)
        assert not _packed(app._out_section)
        assert _packed(app._batch_frame)
        assert app._btn.cget("text") == "Encrypt Files →"

    def test_batch_mode_forgets_a_single_selection(self, mkapp, tmp_path):
        app = mkapp()
        src = tmp_path / "a.bin"
        src.write_bytes(b"x")
        app._on_file(str(src))
        app._src_type.set("batch")
        app.update()
        assert app._path is None and app._is_folder is False

    def test_the_button_counts_the_batch(self, mkapp, tmp_path):
        app = mkapp()
        paths = []
        for i in range(2):
            p = tmp_path / f"f{i}.bin"
            p.write_bytes(b"x")
            paths.append(str(p))
        app._set_batch_paths(paths)
        app._src_type.set("batch")
        app.update()
        assert app._btn.cget("text") == "Encrypt 2 Files →"

    def test_leaving_folder_mode_clears_the_folder_selection(self, mkapp, tmp_path):
        app = mkapp()
        folder = tmp_path / "tree"
        folder.mkdir()
        (folder / "a.txt").write_text("x")
        app._src_type.set("folder")
        app._on_folder(str(folder))
        app.update()
        app._src_type.set("file")
        app.update()
        assert app._path is None and app._is_folder is False
        assert "Select a file to encrypt" in _widget_texts(app._file_card)

    def test_entering_folder_mode_clears_a_file_selection(self, mkapp, tmp_path):
        app = mkapp()
        src = tmp_path / "a.bin"
        src.write_bytes(b"x")
        app._on_file(str(src))
        app._src_type.set("folder")
        app.update()
        assert app._path is None
        assert "Select a folder to encrypt" in _widget_texts(app._file_card)

    def test_switching_back_to_file_restores_the_output_row(self, mkapp):
        app = mkapp()
        app._src_type.set("batch")
        app.update()
        app._src_type.set("file")
        app.update()
        assert _packed(app._out_section)
        assert _packed(app._file_card)


@requires_tkinter
class TestDragAndDrop:
    """Contract: one folder → folder mode, one file → file mode, several files
    (or any drop while in batch mode) → batch."""

    def _drop(self, app, data):
        app._on_drop(types.SimpleNamespace(data=data))
        app.update()

    def test_a_single_file_loads_file_mode(self, mkapp, tmp_path):
        app = mkapp()
        src = tmp_path / "dropped.bin"
        src.write_bytes(b"x" * 10)
        self._drop(app, str(src))
        assert app._src_type.get() == "file"
        assert app._path == str(src)
        assert "dropped.bin" in _widget_texts(app._file_card)

    def test_a_single_folder_switches_to_folder_mode(self, mkapp, tmp_path):
        app = mkapp()
        folder = tmp_path / "tree"
        folder.mkdir()
        (folder / "a.txt").write_text("x")
        self._drop(app, str(folder))
        assert app._src_type.get() == "folder"
        assert app._path == str(folder) and app._is_folder is True

    def test_several_files_switch_to_batch(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        a, b = tmp_path / "a.bin", tmp_path / "b.bin"
        for p in (a, b):
            p.write_bytes(b"x")
        self._drop(app, "{%s} {%s}" % (a, b))
        assert app._src_type.get() == "batch"
        assert app._batch_paths == [str(a), str(b)]

    def test_one_file_dropped_in_batch_mode_stays_batch(self, mkapp, tmp_path):
        app = mkapp()
        src = tmp_path / "a.bin"
        src.write_bytes(b"x")
        app._src_type.set("batch")
        app.update()
        self._drop(app, str(src))
        assert app._src_type.get() == "batch"
        assert app._batch_paths == [str(src)]

    def test_refusing_the_replacement_keeps_the_current_batch(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        keep = [str(tmp_path / "k1.bin"), str(tmp_path / "k2.bin")]
        for p in keep:
            open(p, "wb").write(b"x")
        app._set_batch_paths(keep)
        app._src_type.set("batch")
        app.update()
        monkeypatch.setattr(enc, "confirm", _Confirms(False))
        a, b = tmp_path / "a.bin", tmp_path / "b.bin"
        for p in (a, b):
            p.write_bytes(b"x")
        self._drop(app, "{%s} {%s}" % (a, b))
        assert app._batch_paths == keep

    def test_a_drop_while_busy_is_ignored(self, mkapp, tmp_path):
        app = mkapp()
        src = tmp_path / "a.bin"
        src.write_bytes(b"x")
        app._busy = True
        self._drop(app, str(src))
        assert app._path is None
        # Positive control: the same drop lands the moment the job is over,
        # so "nothing happened" above is the busy guard and not a dead handler.
        app._busy = False
        self._drop(app, str(src))
        assert app._path == str(src)

    def test_a_drop_payload_tcl_cannot_split_is_parsed_by_hand(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        # A brace in a filename makes the Tcl list unbalanced, so splitlist
        # raises and the hand-rolled fallback parser has to recover both paths.
        a, b = tmp_path / "week{1.bin", tmp_path / "b.bin"
        for p in (a, b):
            p.write_bytes(b"x")
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        with pytest.raises(tk.TclError):
            app.tk.splitlist("{%s} {%s}" % (a, b))
        self._drop(app, "{%s} {%s}" % (a, b))
        assert app._batch_paths == [str(a), str(b)]

    def test_dropping_nothing_usable_changes_nothing(self, mkapp, tmp_path):
        app = mkapp()
        self._drop(app, str(tmp_path / "does-not-exist.bin"))
        assert app._path is None and app._batch_paths == []
        assert app._err.cget("text") == ""
        # Positive control: a path that DOES exist is taken, so the handler
        # was live and the missing file is what it rejected.
        real = tmp_path / "real.bin"
        real.write_bytes(b"x")
        self._drop(app, str(real))
        assert app._path == str(real)


# ─────────────────────────────────────────────────────────────────────────────
# Batch source UI
# ─────────────────────────────────────────────────────────────────────────────

@requires_tkinter
class TestBatchListUI:
    """Contract: the batch panel shows what will be encrypted, where it goes,
    and never grows past five rows."""

    def _paths(self, tmp_path, n, size=16):
        out = []
        for i in range(n):
            p = tmp_path / f"file{i}.bin"
            p.write_bytes(b"x" * size)
            out.append(str(p))
        return out

    def test_an_empty_batch_offers_the_picker(self, mkapp):
        app = mkapp()
        app._src_type.set("batch")
        app.update()
        texts = _widget_texts(app._batch_frame)
        assert "Select files →" in texts
        assert any("Select multiple files" in t for t in texts)

    def test_a_batch_lists_its_files_and_defaults_the_output_folder(self, mkapp, tmp_path):
        app = mkapp()
        paths = self._paths(tmp_path, 3)
        app._set_batch_paths(paths)
        app._src_type.set("batch")
        app._build_batch_ui()
        app.update()
        texts = _widget_texts(app._batch_frame)
        assert "3 files selected" in texts
        assert {"file0.bin", "file1.bin", "file2.bin"} <= set(texts)
        assert app._batch_out_var.get() == str(tmp_path)

    def test_only_five_rows_are_shown(self, mkapp, tmp_path):
        app = mkapp()
        app._set_batch_paths(self._paths(tmp_path, 7))
        app._src_type.set("batch")
        app._build_batch_ui()
        app.update()
        texts = _widget_texts(app._batch_frame)
        assert "file4.bin" in texts and "file5.bin" not in texts
        assert "  … and 2 more files" in texts

    def test_a_vanished_file_shows_an_unknown_size(self, mkapp, tmp_path):
        app = mkapp()
        paths = self._paths(tmp_path, 2)
        gone = str(tmp_path / "vanished.bin")
        app._set_batch_paths(paths + [gone])
        app._src_type.set("batch")
        app._build_batch_ui()
        app.update()
        assert "?" in _widget_texts(app._batch_frame)

    def test_the_output_folder_the_user_chose_survives_a_retry(self, mkapp, tmp_path):
        app = mkapp()
        paths = self._paths(tmp_path, 2)
        app._set_batch_paths(paths)
        app._src_type.set("batch")
        app._build_batch_ui()
        chosen = str(tmp_path / "elsewhere")
        os.mkdir(chosen)
        app._batch_out_var.set(chosen)
        app._set_batch_paths(paths[:1], keep_out=True)
        assert app._batch_out_var.get() == chosen
        app._set_batch_paths(paths[:1])          # without keep_out it re-defaults
        assert app._batch_out_var.get() == str(tmp_path)

    def test_replacing_one_file_needs_no_confirmation(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        conf = _Confirms(False)
        monkeypatch.setattr(enc, "confirm", conf)
        app._set_batch_paths(self._paths(tmp_path, 1))
        assert app._confirm_replace_batch() is True
        assert conf.calls == []

    def test_replacing_several_files_asks_first(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        conf = _Confirms(False)
        monkeypatch.setattr(enc, "confirm", conf)
        app._set_batch_paths(self._paths(tmp_path, 3))
        assert app._confirm_replace_batch() is False
        assert "3 files selected" in conf.message_for("Replace selection?")

    def test_picking_files_replaces_the_list_and_relabels_the_button(
            self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        paths = self._paths(tmp_path, 2)
        monkeypatch.setattr(enc, "filedialog", _Dialogs(openfiles=tuple(paths)))
        app._src_type.set("batch")
        app.update()
        app._on_batch_select()
        app.update()
        assert app._batch_paths == paths
        assert app._btn.cget("text") == "Encrypt 2 Files →"
        assert "2 files selected" in _widget_texts(app._batch_frame)

    def test_cancelling_the_picker_keeps_the_previous_list(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        paths = self._paths(tmp_path, 1)
        app._set_batch_paths(paths)
        dlg = _Dialogs(openfiles=())
        monkeypatch.setattr(enc, "filedialog", dlg)
        app._on_batch_select()
        # The picker really opened and answered "nothing"; an empty answer is
        # not allowed to clear a selection the user already made.
        assert [c[0] for c in dlg.calls] == ["askopenfilenames"]
        assert app._batch_paths == paths

    def test_refusing_the_replace_prompt_skips_the_picker(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        paths = self._paths(tmp_path, 3)
        app._set_batch_paths(paths)
        conf = _Confirms(False)
        monkeypatch.setattr(enc, "confirm", conf)
        dlg = _Dialogs(openfiles=("/nope",))
        monkeypatch.setattr(enc, "filedialog", dlg)
        app._on_batch_select()
        assert conf.titles == ["Replace selection?"]
        assert app._batch_paths == paths and dlg.calls == []

    def test_browsing_sets_the_output_folder(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        app._set_batch_paths(self._paths(tmp_path, 1))
        app._src_type.set("batch")
        app._build_batch_ui()
        target = str(tmp_path / "out")
        os.mkdir(target)
        monkeypatch.setattr(enc, "filedialog", _Dialogs(directory=target))
        app._browse_batch_out()
        assert app._batch_out_var.get() == target

    def test_cancelling_the_folder_browser_keeps_the_current_folder(
            self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        app._set_batch_paths(self._paths(tmp_path, 1))
        app._src_type.set("batch")
        app._build_batch_ui()
        before = app._batch_out_var.get()
        dlg = _Dialogs(directory="")
        monkeypatch.setattr(enc, "filedialog", dlg)
        app._browse_batch_out()
        assert [c[0] for c in dlg.calls] == ["askdirectory"]
        assert app._batch_out_var.get() == before


# ─────────────────────────────────────────────────────────────────────────────
# Protection + secret steps
# ─────────────────────────────────────────────────────────────────────────────

@requires_tkinter
class TestModeSwitch:
    """Contract: password fields and share controls swap, and the disabled
    half leaves the Tab order."""

    def test_single_mode_shows_the_password_panel(self, mkapp):
        app = mkapp()
        assert _packed(app._pw_panel)
        assert not _packed(app._sh_panel)
        assert app._secret_lbl.cget("text") == "3  PASSWORD"
        assert str(app._pw1.cget("state")) == "normal"

    def test_split_mode_swaps_to_the_share_panel(self, mkapp):
        app = mkapp()
        app._mode.set("shamir")
        app.update()
        assert _packed(app._sh_panel)
        assert not _packed(app._pw_panel)
        assert app._secret_lbl.cget("text") == "3  SHARES"
        # Disabled, so Tab skips fields the user cannot use in this mode.
        assert str(app._pw1.cget("state")) == "disabled"
        assert str(app._pw2.cget("state")) == "disabled"

    def test_switching_back_re_enables_the_password_fields(self, mkapp):
        app = mkapp()
        app._mode.set("shamir")
        app._mode.set("single")
        app.update()
        assert str(app._pw1.cget("state")) == "normal"

    def test_the_hint_explains_the_current_mode(self, mkapp):
        app = mkapp()
        assert "only way to unlock" in app._mode_hint.cget("text")
        app._mode.set("shamir")
        assert "combine their shares" in app._mode_hint.cget("text")

    def test_an_open_help_box_survives_a_round_trip_through_single_mode(self, mkapp):
        app = mkapp()
        app._mode.set("shamir")
        app._toggle_shamir_help()
        app.update()
        assert _packed(app._shamir_help)
        app._mode.set("single")
        app._mode.set("shamir")
        app.update()
        assert _packed(app._shamir_help)


@requires_tkinter
class TestPasswordFields:
    """Contract: each field reveals independently, and the match indicator is
    silent until there is something to compare."""

    def test_each_eye_toggles_only_its_own_field(self, mkapp):
        app = mkapp()
        app._toggle_pw(1)
        assert app._pw1.cget("show") == "" and app._eye1_btn.cget("text") == "Hide"
        assert app._pw2.cget("show") == "•" and app._eye2_btn.cget("text") == "Show"
        app._toggle_pw(2)
        assert app._pw2.cget("show") == "" and app._eye2_btn.cget("text") == "Hide"
        app._toggle_pw(1)
        assert app._pw1.cget("show") == "•" and app._eye1_btn.cget("text") == "Show"

    def test_an_unknown_field_number_changes_nothing(self, mkapp):
        app = mkapp()
        app._toggle_pw()
        assert app._pw1.cget("show") == "•" and app._pw2.cget("show") == "•"

    def test_the_match_indicator_follows_both_fields(self, mkapp):
        app = mkapp()
        assert app._match_lbl.cget("text") == ""
        app._pw1v.set("hunter22")
        assert app._match_lbl.cget("text") == ""      # nothing to compare yet
        app._pw2v.set("hunter2")
        assert app._match_lbl.cget("text") == "✗  Don't match"
        assert app._match_lbl.cget("fg") == enc.C["error"]
        app._pw2v.set("hunter22")
        assert app._match_lbl.cget("text") == "✓  Passwords match"
        assert app._match_lbl.cget("fg") == enc.C["success"]

    def test_unicode_and_very_long_passwords_still_compare(self, mkapp):
        app = mkapp()
        long_pw = "🔐 mot de passe très très long " * 40
        app._pw1v.set(long_pw)
        app._pw2v.set(long_pw)
        assert app._match_lbl.cget("text") == "✓  Passwords match"
        assert app._secret_ok() is True


@requires_tkinter
class TestShamirControls:
    """Contract: k and n stay inside 2…20 with k ≤ n, the presets set both at
    once, and the summary always describes what will actually happen."""

    def _bump_buttons(self, app):
        """The − / + buttons of the (k, n) cards, in document order."""
        found = []
        def walk(w):
            for child in w.winfo_children():
                if isinstance(child, enc.FlatButton) and child.cget("text") in ("−", "+"):
                    found.append(child)
                walk(child)
        walk(app._shamir_grid)
        return found

    def test_the_help_box_toggles(self, mkapp):
        app = mkapp()
        app._mode.set("shamir")
        app.update()
        assert not _packed(app._shamir_help)
        app._toggle_shamir_help()
        app.update()
        assert _packed(app._shamir_help)
        assert any("vault that needs multiple keys" in t
                   for t in _widget_texts(app._shamir_help))
        app._toggle_shamir_help()
        app.update()
        assert not _packed(app._shamir_help)

    def _tinted(self, app):
        return {key for key, btn in app._preset_btns.items()
                if btn.cget("bg") == enc.C["accent"]}

    def test_the_preset_matching_the_spinboxes_is_tinted(self, mkapp):
        app = mkapp()
        # 3-of-5 first: the wizard opens on 2-of-3, so asserting the default
        # is tinted would pass even if _refresh_presets did nothing at all.
        app._n.set(5); app._k.set(3)
        app._refresh_presets()
        assert self._tinted(app) == {(5, 3)}
        app._n.set(3); app._k.set(2)
        app._refresh_presets()
        assert self._tinted(app) == {(3, 2)}, "the old tint must move, not accumulate"
        app._n.set(4); app._k.set(2)          # no preset for 2-of-4
        app._refresh_presets()
        assert self._tinted(app) == set()

    def test_clicking_a_preset_sets_both_numbers(self, mkapp):
        app = mkapp()
        app._preset_btns[(7, 3)]._fire()
        assert (app._n.get(), app._k.get()) == (7, 3)
        assert self._tinted(app) == {(7, 3)}
        assert app._shamir_summary.cget("text") == "Any 3 of 7 people can unlock the file"

    def test_an_unreadable_spinbox_tints_nothing(self, mkapp):
        app = mkapp()
        assert self._tinted(app) == {(3, 2)}     # the wizard opens on 2-of-3
        app._n.set("")            # what an emptied field looks like to IntVar
        app._refresh_presets()
        assert self._tinted(app) == set()

    def test_the_step_buttons_move_one_at_a_time_and_stop_at_the_edges(self, mkapp):
        app = mkapp()
        minus_k, plus_k, minus_n, plus_n = self._bump_buttons(app)
        app._k.set(2)
        minus_k._fire()
        assert app._k.get() == 2                 # 2 is the floor
        plus_k._fire()
        assert app._k.get() == 3
        app._n.set(20)
        plus_n._fire()
        assert app._n.get() == 20                # 20 is the ceiling
        minus_n._fire()
        assert app._n.get() == 19

    def test_stepping_an_emptied_field_recovers_from_the_minimum(self, mkapp):
        app = mkapp()
        minus_k, plus_k, _minus_n, _plus_n = self._bump_buttons(app)
        app._k.set("")
        plus_k._fire()
        assert app._k.get() == 3          # stepped up from the assumed 2
        app._k.set("")
        minus_k._fire()
        assert app._k.get() == 2          # and down from it, clamped at the floor

    def test_the_summary_tracks_typing_before_the_clamp_lands(self, mkapp):
        app = mkapp()
        app._n.set(5); app._k.set(3)
        assert app._shamir_summary.cget("text") == "Any 3 of 5 people can unlock the file"
        # Typing "1" on the way to "10" must not flash a clamped value.
        app._n.set(1)
        assert app._shamir_summary.cget("text") == "Any 2 of 2 people can unlock the file"
        assert app._n.get() == 1, "the field itself is left alone while typing"

    def test_the_deferred_clamp_fixes_the_numbers_and_says_what_it_did(self, mkapp):
        app = mkapp()
        app._n.set(3); app._k.set(9)
        app._do_clamp()
        assert (app._n.get(), app._k.get()) == (3, 3)
        assert "can't exceed total people" in app._err.cget("text")
        assert app._shamir_summary.cget("text") == "Any 3 of 3 people can unlock the file"

    @pytest.mark.parametrize("n, k, expect_n, expect_k, note", [
        (1, 2, 2, 2, "Minimum is 2 people"),
        (25, 2, 20, 2, "Maximum is 20 people"),
        (5, 1, 5, 2, "Minimum is 2 people"),
        (5, 25, 5, 5, "Maximum is 20 people"),
    ])
    def test_every_out_of_range_pair_is_corrected(self, mkapp, n, k, expect_n, expect_k, note):
        app = mkapp()
        app._n.set(n); app._k.set(k)
        app._do_clamp()
        assert (app._n.get(), app._k.get()) == (expect_n, expect_k)
        assert note in app._err.cget("text")

    def test_a_valid_pair_is_left_alone_and_says_nothing(self, mkapp):
        app = mkapp()
        app._set_status("")
        app._n.set(5); app._k.set(3)
        app._do_clamp()
        assert (app._n.get(), app._k.get()) == (5, 3)
        assert app._err.cget("text") == ""

    def test_an_emptied_field_is_left_for_the_validator_to_report(self, mkapp):
        app = mkapp()
        app._k.set("")
        app._clamp_k()
        app._do_clamp()
        # The clamp must not invent a value the user did not type; the empty
        # field survives and the secret step simply reads as incomplete.
        with pytest.raises(tk.TclError):
            app._k.get()
        assert app._secret_ok() is False

    def test_a_clamp_job_that_already_fired_is_not_an_error(self, mkapp):
        app = mkapp()
        app._clamp_job = "after#already-fired"
        app._n.set(4)
        assert app._clamp_job not in (None, "after#already-fired")
        assert app._shamir_summary.cget("text") == "Any 2 of 4 people can unlock the file"

    def test_a_second_keystroke_replaces_the_pending_clamp(self, mkapp):
        app = mkapp()
        app._n.set(1)
        first = app._clamp_job
        app._n.set(15)
        assert app._clamp_job != first
        # The superseded job must be gone, not merely ignored.
        assert first not in app.tk.call("after", "info")


@requires_tkinter
class TestSecretOk:
    """Contract: ``_secret_ok`` is what drives the wizard highlight."""

    def test_single_mode_needs_two_matching_non_empty_passwords(self, mkapp):
        app = mkapp()
        assert app._secret_ok() is False
        app._pw1v.set("hunter22")
        assert app._secret_ok() is False
        app._pw2v.set("hunter22")
        assert app._secret_ok() is True

    @pytest.mark.parametrize("n, k, ok", [
        (2, 2, True), (20, 20, True), (3, 2, True),
        (1, 2, False), (21, 2, False), (3, 4, False), (3, 1, False),
    ])
    def test_split_mode_bounds(self, mkapp, n, k, ok):
        app = mkapp()
        app._mode.set("shamir")
        app._n.set(n); app._k.set(k)
        assert app._secret_ok() is ok

    def test_an_emptied_field_is_not_ok(self, mkapp):
        app = mkapp()
        app._mode.set("shamir")
        app._n.set("")
        assert app._secret_ok() is False


@requires_tkinter
class TestWizardHighlight:
    """Contract: the step tracker follows the form — source, protection,
    secret, output — and freezes once a run is under way."""

    def test_the_highlight_walks_the_form(self, mkapp, tmp_path):
        app = mkapp()
        assert app._wiz._active == 0
        src = tmp_path / "a.bin"
        src.write_bytes(b"x")
        app._path = str(src)
        app._out.delete(0, "end")
        app._refresh_step()
        assert app._wiz._active == 1              # secret still incomplete
        app._pw1v.set("hunter22"); app._pw2v.set("hunter22")
        assert app._wiz._active == 2              # no output path yet
        app._out.insert(0, str(tmp_path / "a.qcx"))
        app._refresh_step()
        assert app._wiz._active == 3

    def test_batch_mode_reads_the_batch_output_folder(self, mkapp, tmp_path):
        app = mkapp()
        p = tmp_path / "a.bin"
        p.write_bytes(b"x")
        app._set_batch_paths([str(p)])
        app._src_type.set("batch")
        app._build_batch_ui()
        app._pw1v.set("hunter22"); app._pw2v.set("hunter22")
        app._refresh_step()
        assert app._wiz._active == 3
        app._batch_out_var.set("   ")
        app._refresh_step()
        assert app._wiz._active == 2

    def test_a_running_job_pins_the_highlight(self, mkapp):
        app = mkapp()
        app._wiz.set_step(4)
        app._busy = True
        app._refresh_step()
        assert app._wiz._active == 4
        # Positive control: the form is empty, so the moment the job is over
        # the same call recomputes the highlight back to Source.
        app._busy = False
        app._refresh_step()
        assert app._wiz._active == 0

    def test_a_finished_run_pins_the_highlight(self, mkapp):
        app = mkapp()
        app._wiz.set_step(5)
        app._show_done = True
        app._refresh_step()
        assert app._wiz._active == 5
        app._show_done = False
        app._refresh_step()
        assert app._wiz._active == 0


@requires_tkinter
class TestFreezeThaw:
    """Contract: nothing about the job can be changed while it runs."""

    def test_freeze_locks_every_input(self, mkapp, tmp_path):
        dec = tmp_path / "decryptor"
        dec.write_bytes(b"binary")
        app = mkapp(find_dec=str(dec))
        app._freeze()
        assert app._btn._enabled is False
        assert app._browse_btn._enabled is False
        assert str(app._pw1.cget("state")) == "disabled"
        assert str(app._pw2.cget("state")) == "disabled"
        assert str(app._out.cget("state")) == "disabled"
        assert str(app._embed_chk.cget("state")) == "disabled"
        assert int(app._file_card.cget("takefocus")) == 0

    def test_thaw_restores_them(self, mkapp, tmp_path):
        dec = tmp_path / "decryptor"
        dec.write_bytes(b"binary")
        app = mkapp(find_dec=str(dec))
        app._freeze()
        app._thaw()
        assert app._btn._enabled is True
        assert str(app._pw1.cget("state")) == "normal"
        assert str(app._out.cget("state")) == "normal"
        assert str(app._embed_chk.cget("state")) == "normal"
        assert int(app._file_card.cget("takefocus")) == 1

    def test_freezing_works_without_the_portable_file_section(self, mkapp):
        # Running from source with no built binary: there is no embed
        # checkbox to disable, and freezing must not care.
        app = mkapp()
        assert not hasattr(app, "_embed_chk")
        app._freeze()
        assert app._btn._enabled is False and str(app._out.cget("state")) == "disabled"
        app._thaw()
        assert app._btn._enabled is True and str(app._pw1.cget("state")) == "normal"

    def test_thaw_keeps_the_password_fields_out_of_split_mode(self, mkapp):
        app = mkapp()
        app._mode.set("shamir")
        app._freeze()
        app._thaw()
        # The thaw ran (the button and output are live again) but deliberately
        # left the password fields out of the Tab order for this mode.
        assert app._btn._enabled is True
        assert str(app._out.cget("state")) == "normal"
        assert str(app._pw1.cget("state")) == "disabled"
        assert str(app._pw2.cget("state")) == "disabled"


@requires_tkinter
class TestEmbedDecryptor:
    """Contract: the PORTABLE FILE section only exists when a usable binary
    does, and it always says what the choice costs."""

    def test_without_a_binary_the_section_is_not_built(self, mkapp):
        app = mkapp()
        assert "PORTABLE FILE" not in _widget_texts(app)
        assert not hasattr(app, "_embed_chk")

    def test_ticking_the_box_without_a_binary_unticks_itself(self, mkapp):
        app = mkapp()
        app._embed_dec.set(True)
        app._on_embed_toggle()
        assert app._embed_dec.get() is False
        assert app._embed_hint.cget("text").startswith("Decryptor binary not found")

    def test_with_a_binary_the_hint_quotes_its_size(self, mkapp, tmp_path):
        dec = tmp_path / "decryptor"
        dec.write_bytes(b"z" * 2048)
        app = mkapp(find_dec=str(dec))
        assert "PORTABLE FILE" in _widget_texts(app)
        app._embed_dec.set(True)
        app._on_embed_toggle()
        assert "2.0 KB larger" in app._embed_hint.cget("text")
        app._embed_dec.set(False)
        app._on_embed_toggle()
        assert app._embed_hint.cget("text").startswith("Recipients will need")

    def test_a_binary_that_vanished_still_produces_a_hint(self, mkapp, tmp_path):
        dec = tmp_path / "decryptor"
        dec.write_bytes(b"z" * 16)
        app = mkapp(find_dec=str(dec))
        dec.unlink()
        app._embed_dec.set(True)
        app._on_embed_toggle()
        assert "some bytes larger" in app._embed_hint.cget("text")


@requires_tkinter
class TestFindDecryptor:
    """Contract: the probe finds a standalone decryptor beside the module (or
    in its dist/), and refuses to offer one from a frozen build.

    Marked: without a real tkinter the whole class object is a MagicMock, so
    ``_find_dec`` would answer with another mock instead of a path."""

    def test_a_frozen_build_never_offers_an_embed(self, monkeypatch, tmp_path):
        # A binary IS sitting where the probe looks, so returning None can
        # only be the frozen check — not "the search found nothing".
        monkeypatch.setattr(enc, "__file__", str(tmp_path / "encryptor.py"))
        (tmp_path / ".quantacrypt-decryptor").write_bytes(b"bin")
        monkeypatch.setattr(enc.sys, "frozen", False, raising=False)
        assert EncryptorApp._find_dec(object()) == str(tmp_path / ".quantacrypt-decryptor")
        monkeypatch.setattr(enc.sys, "frozen", True, raising=False)
        assert EncryptorApp._find_dec(object()) is None

    def test_a_binary_next_to_the_module_is_found(self, monkeypatch, tmp_path):
        monkeypatch.setattr(enc.sys, "frozen", False, raising=False)
        monkeypatch.setattr(enc, "__file__", str(tmp_path / "encryptor.py"))
        target = tmp_path / ".quantacrypt-decryptor"
        target.write_bytes(b"bin")
        assert EncryptorApp._find_dec(object()) == str(target)

    def test_a_binary_in_dist_is_found(self, monkeypatch, tmp_path):
        monkeypatch.setattr(enc.sys, "frozen", False, raising=False)
        monkeypatch.setattr(enc, "__file__", str(tmp_path / "encryptor.py"))
        dist = tmp_path / "dist"
        dist.mkdir()
        target = dist / "quantacrypt"
        target.write_bytes(b"bin")
        assert EncryptorApp._find_dec(object()) == str(target)

    def test_nothing_installed_means_no_embed(self, monkeypatch, tmp_path):
        monkeypatch.setattr(enc.sys, "frozen", False, raising=False)
        monkeypatch.setattr(enc, "__file__", str(tmp_path / "encryptor.py"))
        (tmp_path / "dist").mkdir()
        assert EncryptorApp._find_dec(object()) is None


# ─────────────────────────────────────────────────────────────────────────────
# Output step
# ─────────────────────────────────────────────────────────────────────────────

@requires_tkinter
class TestOutputPath:
    """Contract: the output path is auto-derived from the source until the
    user touches it, and then it is theirs."""

    def test_choosing_a_file_derives_the_output_and_the_title(self, mkapp, tmp_path):
        app = mkapp()
        src = tmp_path / "report.pdf"
        src.write_bytes(b"%PDF")
        app._on_file(str(src))
        assert app._out.get() == str(tmp_path / "report.qcx")
        assert app._out_auto is True
        assert app.title() == "report.pdf — QuantaCrypt · Encrypt"
        assert "Auto-generated" in app._out_hint.cget("text")

    def test_a_second_file_replaces_an_auto_path(self, mkapp, tmp_path):
        app = mkapp()
        for name in ("a.bin", "b.bin"):
            p = tmp_path / name
            p.write_bytes(b"x")
            app._on_file(str(p))
        assert app._out.get() == str(tmp_path / "b.qcx")

    def test_a_hand_edited_path_is_never_overwritten(self, mkapp, tmp_path):
        app = mkapp()
        a = tmp_path / "a.bin"
        a.write_bytes(b"x")
        app._on_file(str(a))
        mine = str(tmp_path / "my choice.qcx")
        app._out.delete(0, "end")
        app._out.insert(0, mine)
        app._out_auto = False
        b = tmp_path / "b.bin"
        b.write_bytes(b"x")
        app._on_file(str(b))
        assert app._out.get() == mine

    def test_typing_in_the_field_marks_it_user_supplied(self, mkapp, tmp_path):
        app = mkapp()
        src = tmp_path / "a.bin"
        src.write_bytes(b"x")
        app._on_file(str(src))
        assert app._out_auto is True
        _press(app, "<Key>", widget=app._out, keysym="x")
        assert app._out_auto is False

    def test_navigation_keys_do_not_count_as_editing(self, mkapp, tmp_path):
        app = mkapp()
        src = tmp_path / "a.bin"
        src.write_bytes(b"x")
        app._on_file(str(src))
        _press(app, "<Key>", widget=app._out, keysym="Tab")
        assert app._out_auto is True

    def test_choosing_a_folder_derives_a_sibling_output(self, mkapp, tmp_path):
        app = mkapp()
        folder = tmp_path / "photos"
        folder.mkdir()
        (folder / "a.jpg").write_bytes(b"x" * 100)
        app._src_type.set("folder")
        app._on_folder(str(folder))
        assert app._out.get() == str(tmp_path / "photos.qcx")
        assert app._is_folder is True
        assert app.title() == "photos/ — QuantaCrypt · Encrypt"

    def test_the_folder_scan_reports_real_totals(self, mkapp, tmp_path):
        app = mkapp()
        folder = tmp_path / "photos"
        folder.mkdir()
        for i in range(3):
            (folder / f"{i}.jpg").write_bytes(b"x" * 1024)
        app._src_type.set("folder")
        app._on_folder(str(folder))
        assert "Scanning folder…" in _widget_texts(app._file_card)
        assert _pump_until(app, lambda: "Scanning folder…" not in _widget_texts(app._file_card), 10)
        line = app._file_card._line2.cget("text")
        assert line.startswith("3 files  ·  3.1 KB")

    def test_an_unreadable_folder_scans_to_zero(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        folder = tmp_path / "locked"
        folder.mkdir()
        def _boom(_p):
            raise PermissionError("nope")
        monkeypatch.setattr(enc, "_folder_stats", _boom)
        app._src_type.set("folder")
        app._on_folder(str(folder))
        assert _pump_until(app, lambda: "0 files" in app._file_card._line2.cget("text"), 10)

    def test_browsing_replaces_the_path_and_resets_the_hint(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        src = tmp_path / "a.bin"
        src.write_bytes(b"x")
        app._on_file(str(src))
        chosen = str(tmp_path / "elsewhere.qcx")
        dlg = _Dialogs(savename=chosen)
        monkeypatch.setattr(enc, "filedialog", dlg)
        app._browse_out()
        assert app._out.get() == chosen
        assert app._out_auto is False
        assert app._out_hint.cget("text").startswith(".qcx is QuantaCrypt's")
        # The dialog opens where the current path points, not at $HOME.
        assert dlg.calls[0][1]["initialdir"] == str(tmp_path)

    def test_cancelling_the_browser_keeps_the_current_path(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        src = tmp_path / "a.bin"
        src.write_bytes(b"x")
        app._on_file(str(src))
        before = app._out.get()
        dlg = _Dialogs(savename="")
        monkeypatch.setattr(enc, "filedialog", dlg)
        app._browse_out()
        # The save dialog really opened; an empty answer must not blank the
        # auto-derived path or downgrade it to "user supplied".
        assert [c[0] for c in dlg.calls] == ["asksaveasfilename"]
        assert app._out.get() == before and app._out_auto is True

    def test_browsing_from_an_empty_field_opens_with_no_directory(self, mkapp, monkeypatch):
        app = mkapp()
        dlg = _Dialogs(savename="")
        monkeypatch.setattr(enc, "filedialog", dlg)
        app._browse_out()
        assert dlg.calls[0][1]["initialdir"] == ""


# ─────────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────────

@requires_tkinter
class TestValidateSecret:
    """Contract: the secret step reports exactly what is wrong."""

    def test_an_empty_password_is_named(self, mkapp):
        app = mkapp()
        assert app._validate_secret() == "Password cannot be empty"

    def test_a_mismatch_is_named(self, mkapp):
        app = mkapp()
        app._pw1v.set("hunter22"); app._pw2v.set("hunter23")
        assert app._validate_secret() == "Passwords don't match"

    def test_a_matching_pair_passes(self, mkapp):
        app = mkapp()
        app._pw1v.set("hunter22"); app._pw2v.set("hunter22")
        assert app._validate_secret() is None

    @pytest.mark.parametrize("pw", ["a", "1234567"])
    def test_a_password_below_the_core_floor_is_refused(self, mkapp, pw):
        app = mkapp()
        app._pw1v.set(pw); app._pw2v.set(pw)
        assert app._validate_secret() == (
            f"Use at least {cc.MIN_PASSWORD_LENGTH} characters")

    def test_exactly_the_floor_is_accepted(self, mkapp):
        app = mkapp()
        floor = "x" * cc.MIN_PASSWORD_LENGTH
        app._pw1v.set(floor); app._pw2v.set(floor)
        assert app._validate_secret() is None

    @pytest.mark.parametrize("n, k, msg", [
        (1, 2, "Total shares must be at least 2"),
        (3, 5, "Threshold can't exceed total shares"),
        (3, 1, "Threshold must be at least 2"),
        (21, 2, EncryptorApp._KN_ERR),
    ])
    def test_split_mode_bounds_are_reported(self, mkapp, n, k, msg):
        app = mkapp()
        app._mode.set("shamir")
        app._n.set(n); app._k.set(k)
        assert app._validate_secret() == msg

    def test_an_emptied_field_is_reported_instead_of_silently_failing(self, mkapp):
        app = mkapp()
        app._mode.set("shamir")
        app._n.set("")
        assert app._validate_secret() == EncryptorApp._KN_ERR

    def test_the_valid_corners_pass(self, mkapp):
        app = mkapp()
        app._mode.set("shamir")
        for n, k in ((2, 2), (20, 20), (20, 2)):
            app._n.set(n); app._k.set(k)
            assert app._validate_secret() is None


@requires_tkinter
class TestValidateSingle:
    """Contract: nothing is encrypted until the source, the destination and
    the secret are all usable."""

    def _ready(self, app, tmp_path, name="a.bin"):
        src = tmp_path / name
        src.write_bytes(b"payload")
        app._path = str(src)
        app._out.delete(0, "end")
        app._out.insert(0, str(tmp_path / "out.qcx"))
        app._pw1v.set(PW); app._pw2v.set(PW)
        return src

    def test_a_complete_form_validates(self, mkapp, tmp_path):
        app = mkapp()
        self._ready(app, tmp_path)
        assert app._validate() is None

    def test_no_source(self, mkapp):
        app = mkapp()
        assert app._validate() == "Select a file or folder first"

    def test_a_deleted_file(self, mkapp, tmp_path):
        app = mkapp()
        src = self._ready(app, tmp_path)
        src.unlink()
        assert app._validate() == "Select a file first"

    def test_a_deleted_folder(self, mkapp, tmp_path):
        app = mkapp()
        self._ready(app, tmp_path)
        app._is_folder = True
        app._path = str(tmp_path / "gone")
        assert app._validate() == "Folder no longer exists. Please re-select"

    def test_an_empty_output_path(self, mkapp, tmp_path):
        app = mkapp()
        self._ready(app, tmp_path)
        app._out.delete(0, "end")
        app._out.insert(0, "   ")
        assert app._validate() == "Specify an output path"

    def test_writing_over_the_source(self, mkapp, tmp_path):
        app = mkapp()
        src = self._ready(app, tmp_path)
        app._out.delete(0, "end")
        app._out.insert(0, str(src))
        assert app._validate() == (
            "Output path is the same as the input. Choose a different location")

    def test_a_stat_failure_does_not_abort_validation(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        self._ready(app, tmp_path)
        (tmp_path / "out.qcx").write_bytes(b"an earlier run")   # so samefile runs
        def _boom(a, b):
            raise OSError("stat failed")
        monkeypatch.setattr(enc.os.path, "samefile", _boom)
        # The identity check is a courtesy; a filesystem that cannot answer
        # must not block an otherwise valid run.
        assert app._validate() is None

    def test_an_output_inside_the_source_folder(self, mkapp, tmp_path):
        app = mkapp()
        folder = tmp_path / "tree"
        folder.mkdir()
        app._path = str(folder)
        app._is_folder = True
        app._pw1v.set(PW); app._pw2v.set(PW)
        app._out.delete(0, "end")
        app._out.insert(0, str(folder / "inside.qcx"))
        assert app._validate() == "Output must be outside the folder being encrypted"

    def test_an_output_beside_the_source_folder_is_fine(self, mkapp, tmp_path):
        app = mkapp()
        folder = tmp_path / "tree"
        folder.mkdir()
        app._path = str(folder)
        app._is_folder = True
        app._pw1v.set(PW); app._pw2v.set(PW)
        app._out.delete(0, "end")
        app._out.insert(0, str(tmp_path / "tree.qcx"))
        assert app._validate() is None

    def test_a_sibling_folder_sharing_the_prefix_is_not_inside(self, mkapp, tmp_path):
        app = mkapp()
        folder = tmp_path / "tree"
        folder.mkdir()
        app._path = str(folder)
        app._is_folder = True
        app._pw1v.set(PW); app._pw2v.set(PW)
        app._out.delete(0, "end")
        app._out.insert(0, str(tmp_path / "tree-backup.qcx"))
        assert app._validate() is None

    def test_a_missing_output_directory(self, mkapp, tmp_path):
        app = mkapp()
        self._ready(app, tmp_path)
        missing = tmp_path / "nope"
        app._out.delete(0, "end")
        app._out.insert(0, str(missing / "out.qcx"))
        assert app._validate() == f"Output directory does not exist: {missing}"

    @pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
    def test_a_read_only_output_directory(self, mkapp, tmp_path):
        app = mkapp()
        self._ready(app, tmp_path)
        locked = tmp_path / "locked"
        locked.mkdir()
        os.chmod(locked, 0o500)
        try:
            app._out.delete(0, "end")
            app._out.insert(0, str(locked / "out.qcx"))
            assert app._validate() == f"Output directory is not writable: {locked}"
        finally:
            os.chmod(locked, 0o700)

    def test_the_secret_is_validated_last(self, mkapp, tmp_path):
        app = mkapp()
        self._ready(app, tmp_path)
        app._pw2v.set("different")
        assert app._validate() == "Passwords don't match"

    def test_spaces_quotes_and_unicode_in_the_paths_are_fine(self, mkapp, tmp_path):
        app = mkapp()
        src = tmp_path / "l'été \"2030\" — notes.bin"
        src.write_bytes(b"payload")
        app._path = str(src)
        app._out.delete(0, "end")
        app._out.insert(0, str(tmp_path / "l'été \"2030\" — notes.qcx"))
        app._pw1v.set(PW); app._pw2v.set(PW)
        assert app._validate() is None

    def test_a_very_long_output_name_is_left_to_the_filesystem(self, mkapp, tmp_path):
        # 300 chars is over the usual 255-byte NAME_MAX: the wizard has no
        # opinion about it, so validation passes and the write is what fails.
        app = mkapp()
        src = tmp_path / "a.bin"
        src.write_bytes(b"payload")
        app._path = str(src)
        app._out.delete(0, "end")
        app._out.insert(0, str(tmp_path / ("n" * 300 + ".qcx")))
        app._pw1v.set(PW); app._pw2v.set(PW)
        assert app._validate() is None

    def test_batch_mode_hands_validation_to_the_batch_rules(self, mkapp, tmp_path):
        # _validate is also reachable in batch mode (⌘↵ routes through it);
        # it must not fall through to the single-file "select a file" branch.
        app = mkapp()
        app._src_type.set("batch")
        app.update()
        assert app._validate() == "Select at least one file"
        p = tmp_path / "a.bin"
        p.write_bytes(b"x")
        app._set_batch_paths([str(p)])
        app._build_batch_ui()
        app._pw1v.set(PW); app._pw2v.set(PW)
        assert app._validate() is None


@requires_tkinter
class TestValidateBatch:
    """Contract: the batch path has its own destination rules, then falls
    through to the same secret checks."""

    def _ready(self, app, tmp_path, count=2):
        paths = []
        for i in range(count):
            p = tmp_path / f"f{i}.bin"
            p.write_bytes(b"x")
            paths.append(str(p))
        out = tmp_path / "out"
        out.mkdir(exist_ok=True)
        app._set_batch_paths(paths)
        app._src_type.set("batch")
        app._build_batch_ui()
        app._batch_out_var.set(str(out))
        app._pw1v.set(PW); app._pw2v.set(PW)
        return paths, out

    def test_a_complete_batch_validates(self, mkapp, tmp_path):
        app = mkapp()
        self._ready(app, tmp_path)
        assert app._validate_batch() is None

    def test_no_files(self, mkapp):
        app = mkapp()
        assert app._validate_batch() == "Select at least one file"

    def test_a_file_that_disappeared(self, mkapp, tmp_path):
        app = mkapp()
        paths, _out = self._ready(app, tmp_path)
        os.unlink(paths[0])
        assert app._validate_batch() == "1 file(s) no longer exist. Re-select"

    def test_no_output_folder(self, mkapp, tmp_path):
        app = mkapp()
        self._ready(app, tmp_path)
        app._batch_out_var.set("  ")
        assert app._validate_batch() == "Specify an output folder"

    def test_an_output_folder_before_one_was_ever_offered(self, mkapp, tmp_path):
        app = mkapp()
        p = tmp_path / "a.bin"
        p.write_bytes(b"x")
        app._batch_paths = [str(p)]      # no _batch_out_var yet
        assert app._validate_batch() == "Specify an output folder"

    def test_a_missing_output_folder(self, mkapp, tmp_path):
        app = mkapp()
        self._ready(app, tmp_path)
        missing = tmp_path / "gone"
        app._batch_out_var.set(str(missing))
        assert app._validate_batch() == f"Output folder does not exist: {missing}"

    @pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
    def test_a_read_only_output_folder(self, mkapp, tmp_path):
        app = mkapp()
        _paths, out = self._ready(app, tmp_path)
        os.chmod(out, 0o500)
        try:
            assert app._validate_batch() == f"Output folder is not writable: {out}"
        finally:
            os.chmod(out, 0o700)

    def test_the_secret_is_validated_last(self, mkapp, tmp_path):
        app = mkapp()
        self._ready(app, tmp_path)
        app._pw1v.set("")
        assert app._validate_batch() == "Password cannot be empty"


# ─────────────────────────────────────────────────────────────────────────────
# Progress plumbing
# ─────────────────────────────────────────────────────────────────────────────

@requires_tkinter
class TestPerRunStages:
    """Contract: the dots shown for a run are exactly the stages that will
    happen — no "Compressing folder" for a plain file, no "Securing password"
    in split mode."""

    def test_a_plain_file_with_a_password(self):
        names = [n for _sem, n, _w in EncryptorApp._stages_for(is_folder=False, mode="single")]
        assert names == ["Securing password", "Generating protection",
                         "Locking key", "Encrypting file", "Saving"]

    def test_a_folder_with_a_password_uses_every_stage(self):
        names = [n for _sem, n, _w in EncryptorApp._stages_for(is_folder=True, mode="single")]
        assert names == [n for n, _w in STAGES]

    def test_split_mode_drops_the_password_stage(self):
        sems = [s for s, _n, _w in EncryptorApp._stages_for(is_folder=False, mode="shamir")]
        assert sems == [STAGE_KEM, STAGE_ENCKEY, STAGE_PAYLOAD, STAGE_WRITE]

    def test_a_folder_in_split_mode_keeps_compression(self):
        sems = [s for s, _n, _w in EncryptorApp._stages_for(is_folder=True, mode="shamir")]
        assert sems[0] == STAGE_COMPRESS and STAGE_ARGON not in sems

    def test_new_prog_replaces_the_bar_and_remaps_the_stages(self, mkapp):
        app = mkapp()
        old = app._prog
        app._new_prog(EncryptorApp._stages_for(is_folder=False, mode="shamir"))
        app.update()
        assert not _alive(old), "the previous bar must be destroyed, not stacked"
        assert [n for n, _w in app._prog._stages] == [
            "Generating protection", "Locking key", "Encrypting file", "Saving"]
        assert app._stage_map == {STAGE_KEM: 0, STAGE_ENCKEY: 1,
                                  STAGE_PAYLOAD: 2, STAGE_WRITE: 3}

    def test_a_bar_that_is_already_gone_does_not_block_the_next_run(self, mkapp):
        app = mkapp()
        app._prog.destroy()          # e.g. torn down with a previous result
        app._new_prog(EncryptorApp._stages_for(is_folder=False, mode="single"))
        app.update()
        assert len(app._prog._stages) == 5 and _alive(app._prog)

    def test_advance_shows_the_friendly_label(self, mkapp):
        app = mkapp()
        app._new_prog(EncryptorApp._stages_for(is_folder=False, mode="single"))
        app._busy = True
        app._advance(STAGE_PAYLOAD, "Encrypting payload... 40%")
        assert app._prog._stage_lbl.cget("text") == "Encrypting file  40%"

    def test_a_stage_that_is_not_part_of_this_run_is_ignored(self, mkapp):
        app = mkapp()
        app._new_prog(EncryptorApp._stages_for(is_folder=False, mode="single"))
        app._busy = True
        app._advance(STAGE_PAYLOAD, "Encrypting payload... 40%")
        app._advance(STAGE_COMPRESS, "Compressing folder... 10%")
        assert app._prog._stage_lbl.cget("text") == "Encrypting file  40%"

    def test_a_late_callback_after_the_run_ended_is_ignored(self, mkapp):
        app = mkapp()
        app._new_prog(EncryptorApp._stages_for(is_folder=False, mode="single"))
        app._busy = True
        app._advance(STAGE_KEM)
        app._busy = False
        app._advance(STAGE_WRITE, "Writing binary... 100%")
        assert app._prog._stage_lbl.cget("text") == "Generating protection"

    def test_the_progress_callback_hops_to_the_main_thread(self, mkapp):
        app = mkapp()
        app._new_prog(EncryptorApp._stages_for(is_folder=False, mode="single"))
        app._busy = True
        app._prog_cb("Deriving Argon2 key... 30%")
        assert _pump_until(
            app, lambda: app._prog._stage_lbl.cget("text") == "Securing password  30%", 5)

    def test_an_unrecognised_message_never_touches_the_bar(self, mkapp):
        app = mkapp()
        app._new_prog(EncryptorApp._stages_for(is_folder=False, mode="single"))
        app._busy = True
        app._prog.advance(0, "untouched")
        app._prog_cb("something the core never says")
        app.update()
        # startswith: the shared bar animates trailing dots onto whatever
        # label it was last given.
        assert app._prog._stage_lbl.cget("text").startswith("untouched")


@requires_tkinter
class TestBatchProgress:
    """Contract: one bar for the whole batch — file i's progress stays inside
    file i's slice of it."""

    def test_the_label_names_the_file_and_the_stage(self, mkapp):
        app = mkapp()
        app._new_prog([(STAGE_PAYLOAD, "Encrypting files", 1.0)])
        app._busy = True
        app._advance_batch(1, 4, STAGE_PAYLOAD, 0.5)
        assert app._prog._stage_lbl.cget("text") == "File 1 of 4 — Encrypting file  12%"

    def test_the_last_file_finishing_reads_one_hundred_percent(self, mkapp):
        app = mkapp()
        app._new_prog([(STAGE_PAYLOAD, "Encrypting files", 1.0)])
        app._busy = True
        app._advance_batch(4, 4, STAGE_WRITE, 1.0)
        assert app._prog._stage_lbl.cget("text").endswith("100%")

    def test_nothing_moves_once_the_batch_is_over(self, mkapp):
        app = mkapp()
        app._new_prog([(STAGE_PAYLOAD, "Encrypting files", 1.0)])
        app._prog.advance(0, "untouched")
        app._busy = False
        app._advance_batch(2, 4, STAGE_PAYLOAD, 0.5)
        # startswith: the shared bar animates trailing dots onto whatever
        # label it was last given.
        assert app._prog._stage_lbl.cget("text").startswith("untouched")

    def _pct(self, app):
        return int(re.search(r"(\d+)%", app._prog._stage_lbl.cget("text")).group(1))

    def test_a_files_progress_stays_inside_its_own_slice(self, mkapp):
        app = mkapp()
        app._busy = True
        app._new_prog([(STAGE_PAYLOAD, "Encrypting files", 1.0)])
        app._batch_inner = EncryptorApp._stages_for(is_folder=False, mode="single")
        cb = app._batch_prog_cb(2, 4)
        cb("Deriving Argon2 key... 0%")
        assert _pump_until(app, lambda: "File 2 of 4" in app._prog._stage_lbl.cget("text"), 5)
        low = self._pct(app)
        cb("Writing binary... 100%")
        assert _pump_until(app, lambda: self._pct(app) != low, 5)
        high = self._pct(app)
        # File 2 of 4 owns the 25–50 % band of the overall bar.
        assert 25 <= low < high <= 50

    def test_a_stage_outside_this_runs_plan_is_ignored(self, mkapp):
        app = mkapp()
        app._busy = True
        app._new_prog([(STAGE_PAYLOAD, "Encrypting files", 1.0)])
        app._batch_inner = EncryptorApp._stages_for(is_folder=False, mode="single")
        app._prog.advance(0, "untouched")
        cb = app._batch_prog_cb(1, 2)
        cb("Compressing folder... 50%")      # batch files are never folders
        cb("nothing the core says")
        app.update()
        # startswith: the shared bar animates trailing dots onto whatever
        # label it was last given.
        assert app._prog._stage_lbl.cget("text").startswith("untouched")


# ─────────────────────────────────────────────────────────────────────────────
# Starting a run
# ─────────────────────────────────────────────────────────────────────────────

@requires_tkinter
class TestStartGuards:
    """Contract: every irreversible thing is confirmed first, and refusing
    leaves the form exactly as it was."""

    def _ready(self, app, tmp_path, password=PW):
        src = tmp_path / "in.bin"
        src.write_bytes(b"payload" * 32)
        _fill_single(app, src, tmp_path / "out.qcx", password)
        return src, tmp_path / "out.qcx"

    def test_an_invalid_form_reports_and_starts_nothing(self, mkapp, monkeypatch):
        app = mkapp()
        ran = []
        monkeypatch.setattr(app, "_run", lambda p: ran.append(p))
        app._start()
        app.update()
        assert ran == [] and app._busy is False
        assert app._err.cget("text") == "Select a file or folder first"
        assert app._err.cget("fg") == enc.C["error"]

    def test_a_weak_password_is_challenged_and_can_be_refused(
            self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        ran = []
        monkeypatch.setattr(app, "_run", lambda p: ran.append(p))
        conf = _Confirms(False)
        monkeypatch.setattr(enc, "confirm", conf)
        _src, out = self._ready(app, tmp_path, password="aaaaaaaa")
        app._start()
        app.update()
        assert conf.titles == ["Weak password"]
        assert ran == [] and app._busy is False and not out.exists()

    def test_a_password_the_core_would_refuse_never_reaches_the_weak_dialog(
            self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        ran = []
        monkeypatch.setattr(app, "_run", lambda p: ran.append(p))
        conf = _Confirms(True)
        monkeypatch.setattr(enc, "confirm", conf)
        _src, out = self._ready(app, tmp_path, password="short7")
        app._start()
        app.update()
        # "Use it anyway" on a password encrypt_to_qcx will reject outright
        # would be a dead end, so validation stops it first.
        assert conf.calls == []
        assert ran == [] and not out.exists()
        assert app._err.cget("text") == (
            f"Use at least {cc.MIN_PASSWORD_LENGTH} characters")

    def test_a_strong_password_is_never_challenged(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        ran = []
        monkeypatch.setattr(app, "_run", lambda p: ran.append(p))
        conf = _Confirms(True)
        monkeypatch.setattr(enc, "confirm", conf)
        self._ready(app, tmp_path)
        app._start()
        assert _pump_until(app, lambda: bool(ran), 10)
        assert conf.titles == []

    def test_split_mode_skips_the_password_warning(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        conf = _Confirms(True)
        monkeypatch.setattr(enc, "confirm", conf)
        app._mode.set("shamir")
        assert app._confirm_weak_password() is True
        assert conf.calls == []

    def test_requiring_everybody_is_challenged(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        ran = []
        monkeypatch.setattr(app, "_run", lambda p: ran.append(p))
        conf = _Confirms(False)
        monkeypatch.setattr(enc, "confirm", conf)
        src = tmp_path / "in.bin"
        src.write_bytes(b"x" * 64)
        app._on_file(str(src))
        app._mode.set("shamir")
        app._n.set(3); app._k.set(3)
        app._start()
        app.update()
        assert conf.titles == ["All people required"]
        assert "3-of-3" in conf.message_for("All people required")
        assert ran == [] and app._busy is False

    def test_overwriting_an_existing_file_is_challenged(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        ran = []
        monkeypatch.setattr(app, "_run", lambda p: ran.append(p))
        conf = _Confirms(False)
        monkeypatch.setattr(enc, "confirm", conf)
        _src, out = self._ready(app, tmp_path)
        out.write_bytes(b"precious")
        app._start()
        app.update()
        assert conf.titles == ["Overwrite?"]
        assert ran == [] and out.read_bytes() == b"precious"

    def test_starting_moves_the_wizard_and_freezes_the_form(
            self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        ran = []
        monkeypatch.setattr(app, "_run", lambda p: ran.append(p))
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        src, out = self._ready(app, tmp_path)
        stale = tk.Label(app._results, text="stale result")
        stale.pack()
        app._start()
        assert _pump_until(app, lambda: bool(ran), 10)
        assert app._busy is True
        assert app._wiz._active == 4
        assert app._btn._enabled is False
        assert app._results.winfo_children() == []
        assert _packed(app._cancel_row)
        assert [n for n, _w in app._prog._stages] == [
            "Securing password", "Generating protection", "Locking key",
            "Encrypting file", "Saving"]
        assert ran[0] == {"path": str(src), "out": str(out), "mode": "single",
                          "pw": PW, "n": 3, "k": 2, "embed": False,
                          "is_folder": False}

    def test_a_second_start_while_busy_is_ignored(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        ran = []
        monkeypatch.setattr(app, "_run", lambda p: ran.append(p))
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        self._ready(app, tmp_path)
        app._busy = True
        app._start()
        app.update()
        assert ran == []
        # Positive control: the very same form starts the moment busy clears,
        # so the no-op above is the busy guard and not a broken fixture.
        app._busy = False
        app._start()
        assert _pump_until(app, lambda: bool(ran), 10)

    def test_the_share_numbers_are_frozen_at_start(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        monkeypatch.setattr(app, "_run", lambda p: None)
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        src = tmp_path / "in.bin"
        src.write_bytes(b"x" * 64)
        app._on_file(str(src))
        app._mode.set("shamir")
        app._n.set(5); app._k.set(3)
        app._start()
        app.update()
        # Later drift in the spinboxes must not reach the share artifacts.
        app._n.set(9); app._k.set(4)
        assert (app._result_n, app._result_k) == (5, 3)


# ─────────────────────────────────────────────────────────────────────────────
# The run itself
# ─────────────────────────────────────────────────────────────────────────────

@requires_tkinter
class TestSingleRun:
    """Contract: pressing Encrypt writes a real .qcx that really decrypts, and
    the success card describes it."""

    def test_a_password_run_end_to_end(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        data = b"the quick brown fox" * 500
        src = tmp_path / "in.bin"
        src.write_bytes(data)
        out = tmp_path / "out.qcx"
        _fill_single(app, src, out)
        app._start()
        assert _pump_until(app, lambda: app._busy is False and out.exists(), 60)
        # The file is the real product: it must decrypt back byte for byte.
        restored = tmp_path / "restored"
        restored.mkdir()
        res = pkg.decrypt_qcx(str(out), str(restored), password=PW)
        assert open(res["output"], "rb").read() == data
        texts = _widget_texts(app._results)
        assert "✓  Encrypted successfully" in texts
        assert "out.qcx" in texts
        assert "from  in.bin" in texts
        assert app._wiz._active == len(app.STEPS)
        assert app._show_done is True
        # Passwords are cleared from the form once they are no longer needed.
        assert app._pw1v.get() == "" and app._pw2v.get() == ""
        assert app._match_lbl.cget("text") == ""
        assert app._err.cget("text") == ""

    def test_a_name_with_spaces_quotes_and_unicode_round_trips(
            self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        data = "héllo wörld — l'été\n".encode() * 200
        src = tmp_path / "l'été \"2030\" — notes.txt"
        src.write_bytes(data)
        app._on_file(str(src))
        # The auto-derived output keeps every awkward character of the stem.
        out = tmp_path / "l'été \"2030\" — notes.qcx"
        assert app._out.get() == str(out)
        app._pw1v.set(PW); app._pw2v.set(PW)
        app._start()
        assert _pump_until(app, lambda: app._busy is False and out.exists(), 60)
        restored = tmp_path / "restored"
        restored.mkdir()
        res = pkg.decrypt_qcx(str(out), str(restored), password=PW)
        assert open(res["output"], "rb").read() == data
        assert os.path.basename(res["output"]) == src.name
        assert out.name in _widget_texts(app._results)

    def test_a_folder_run_end_to_end(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        folder = tmp_path / "tree"
        (folder / "sub").mkdir(parents=True)
        (folder / "sub" / "a.txt").write_text("hello")
        out = tmp_path / "tree.qcx"
        app._src_type.set("folder")
        app._on_folder(str(folder))
        app._out.delete(0, "end")
        app._out.insert(0, str(out))
        app._pw1v.set(PW); app._pw2v.set(PW)
        app._start()
        assert _pump_until(app, lambda: app._busy is False and out.exists(), 60)
        assert "from  tree/" in _widget_texts(app._results)
        restored = tmp_path / "restored"
        restored.mkdir()
        res = pkg.decrypt_qcx(str(out), str(restored), password=PW)
        assert res["output"].endswith(".zip")

    def test_the_worker_scrubs_the_password_from_its_parameters(
            self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        src = tmp_path / "in.bin"
        src.write_bytes(b"x" * 64)
        params = {"path": str(src), "out": str(tmp_path / "out.qcx"), "mode": "single",
                  "pw": PW, "n": 3, "k": 2, "embed": False, "is_folder": False}
        app._run(params)
        assert _pump_until(app, lambda: (tmp_path / "out.qcx").exists(), 60)
        assert params["pw"] is None

    def test_an_embedded_decryptor_is_prepended_and_accounted_for(
            self, mkapp, tmp_path, monkeypatch):
        dec = tmp_path / "decryptor"
        dec.write_bytes(b"D" * 4096)
        app = mkapp(find_dec=str(dec))
        src = tmp_path / "in.bin"
        src.write_bytes(b"payload" * 100)
        out = tmp_path / "out.qcx"
        params = {"path": str(src), "out": str(out), "mode": "single", "pw": PW,
                  "n": 3, "k": 2, "embed": True, "is_folder": False}
        app._busy = True                      # as _start would have left it
        app._run(params)
        assert _pump_until(app, lambda: app._busy is False and out.exists(), 60)
        assert out.read_bytes().startswith(b"D" * 4096)
        size_texts = [t for t in _widget_texts(app._results) if "decryptor +" in t]
        assert size_texts and size_texts[0].startswith(enc.fmt_size(out.stat().st_size))
        assert "4.1 KB decryptor" in size_texts[0]
        assert any("chmod +x out.qcx" in t for t in _widget_texts(app._results))

    def test_a_vanished_output_still_produces_a_success_card(self, mkapp, tmp_path):
        # getsize can lose the race with an external mover; the card is the
        # only record of what happened, so it must still render.
        app = mkapp()
        app._busy = True
        app._done(str(tmp_path / "gone.qcx"), [], embedded=False)
        texts = _widget_texts(app._results)
        assert "✓  Encrypted successfully" in texts
        assert "0 B" in texts

    def test_a_decryptor_that_vanishes_mid_run_still_reports_a_size(
            self, mkapp, tmp_path, monkeypatch):
        dec = tmp_path / "decryptor"
        dec.write_bytes(b"D" * 1024)
        app = mkapp(find_dec=str(dec))
        src = tmp_path / "in.bin"
        src.write_bytes(b"payload" * 50)
        out = tmp_path / "out.qcx"
        real_cb = app._prog_cb
        def _cb(msg):
            if "Writing" in msg and dec.exists():
                dec.unlink()          # a rebuild wipes dist/ mid-run
            real_cb(msg)
        monkeypatch.setattr(app, "_prog_cb", _cb)
        app._busy = True
        app._run({"path": str(src), "out": str(out), "mode": "single", "pw": PW,
                  "n": 3, "k": 2, "embed": True, "is_folder": False})
        assert _pump_until(app, lambda: app._busy is False, 60)
        # The bytes are in the file either way; only the breakdown is lost.
        assert out.read_bytes().startswith(b"D" * 1024)
        assert any("0 B decryptor" in t for t in _widget_texts(app._results))

    def test_a_run_that_fails_reports_and_leaves_no_output(
            self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        out = tmp_path / "out.qcx"
        params = {"path": str(tmp_path / "gone.bin"), "out": str(out), "mode": "single",
                  "pw": PW, "n": 3, "k": 2, "embed": False, "is_folder": False}
        app._busy = True
        app._run(params)
        assert _pump_until(app, lambda: app._busy is False, 20)
        assert app._err.cget("text") == "File not found. It may have been moved or deleted."
        assert app._err.cget("fg") == enc.C["error"]
        assert not out.exists()
        assert app._btn._enabled is True          # the form is usable again

    def test_cancelling_a_run_writes_nothing(self, mkapp, tmp_path):
        app = mkapp()
        src = tmp_path / "in.bin"
        src.write_bytes(b"x" * (2 << 20))
        out = tmp_path / "out.qcx"
        app._busy = True
        app._cancel_event.set()                   # as the Cancel button would
        app._run({"path": str(src), "out": str(out), "mode": "single", "pw": PW,
                  "n": 3, "k": 2, "embed": False, "is_folder": False})
        assert _pump_until(app, lambda: app._busy is False, 30)
        assert app._err.cget("text") == "Encryption cancelled. No output was written."
        assert not out.exists()
        assert not list(tmp_path.glob("*.tmp")) and not list(tmp_path.glob(".*qc-enc-*"))
        assert app._wiz._active == 4

    def test_the_cancel_button_arms_the_worker_and_says_so(self, mkapp):
        app = mkapp()
        app._busy = True
        app._cancel_btn.enable(True)
        app._request_cancel()
        assert app._cancel_event.is_set()
        assert app._cancel_btn._enabled is False
        assert app._err.cget("text") == "Cancelling. Finishing the current chunk…"

    def test_cancel_still_arms_the_worker_when_the_button_is_gone(self, mkapp):
        # The button lives in the results area, which a reset can tear down
        # under a click; arming the worker is the part that must survive.
        app = mkapp()
        app._busy = True
        app._cancel_btn.destroy()
        app._request_cancel()
        assert app._cancel_event.is_set()
        assert app._err.cget("text") == "Cancelling. Finishing the current chunk…"

    def test_cancel_does_nothing_when_no_job_is_running(self, mkapp):
        app = mkapp()
        app._request_cancel()
        # A stale Escape or a double click on Cancel must not arm the flag for
        # the NEXT run — _start clears it, but the status line would still lie.
        assert not app._cancel_event.is_set()
        assert app._err.cget("text") == ""
        app._busy = True                 # positive control: it arms when busy
        app._request_cancel()
        assert app._cancel_event.is_set()


@requires_tkinter
class TestFailureMessages:
    """Contract: whatever the worker throws, the user gets a sentence they can
    act on — never a bare traceback string."""

    def _fail(self, app, exc):
        app._busy = True
        app._fail(exc)
        return app._err.cget("text")

    def test_memory_pressure_is_named(self, mkapp):
        app = mkapp()
        assert self._fail(app, MemoryError()) == (
            "File is too large to process. Try a smaller file or free up memory.")

    def test_a_too_large_message_is_treated_the_same(self, mkapp):
        app = mkapp()
        assert self._fail(app, ValueError("chunk Too Large for buffer")).startswith(
            "File is too large")

    def test_a_known_shape_uses_the_shared_vocabulary(self, mkapp):
        app = mkapp()
        assert self._fail(app, PermissionError(13, "denied")).startswith("Access denied")

    def test_an_unmapped_exception_gets_the_generic_advice(self, mkapp):
        app = mkapp()
        msg = self._fail(app, RuntimeError("segment 4 misaligned"))
        assert msg == ("Something went wrong during encryption: segment 4 misaligned. "
                       "Try a different output location or restart the app.")

    def test_a_plain_string_failure_is_shown_as_is(self, mkapp):
        app = mkapp()
        assert self._fail(app, "the helper died") == "the helper died"

    def test_an_empty_string_failure_still_says_something(self, mkapp):
        app = mkapp()
        assert self._fail(app, "").startswith("Something went wrong during encryption")

    def test_failing_unfreezes_the_form(self, mkapp):
        app = mkapp()
        app._freeze()
        self._fail(app, RuntimeError("boom"))
        assert app._busy is False
        assert app._btn._enabled is True
        assert app._wiz._active == 4
        assert not _packed(app._prog)


@requires_tkinter
class TestBatchRun:
    """Contract: every file becomes its own .qcx, one failure does not stop the
    rest, and Cancel leaves the files already written alone."""

    def _arm(self, app):
        """Put the wizard in the state _start_batch leaves behind, so the
        worker can be driven directly without a background thread."""
        app._new_prog([(STAGE_PAYLOAD, "Encrypting files", 1.0)])
        app._batch_inner = EncryptorApp._stages_for(is_folder=False, mode=app._mode.get())
        app._busy = True

    def _batch(self, app, tmp_path, names=("a.bin", "b.bin")):
        paths = []
        for i, name in enumerate(names):
            p = tmp_path / name
            p.write_bytes(bytes([65 + i]) * 200)
            paths.append(str(p))
        out = tmp_path / "out"
        out.mkdir(exist_ok=True)
        app._set_batch_paths(paths)
        app._src_type.set("batch")
        app._build_batch_ui()
        app._batch_out_var.set(str(out))
        app._pw1v.set(PW); app._pw2v.set(PW)
        app.update()
        return paths, out

    def test_a_batch_end_to_end(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        paths, out = self._batch(app, tmp_path)
        app._start()
        assert _pump_until(app, lambda: app._busy is False, 90)
        assert sorted(p.name for p in out.iterdir()) == ["a.qcx", "b.qcx"]
        restored = tmp_path / "restored"
        restored.mkdir()
        res = pkg.decrypt_qcx(str(out / "a.qcx"), str(restored), password=PW)
        assert open(res["output"], "rb").read() == b"A" * 200
        texts = _widget_texts(app._results)
        assert "✓  2 files encrypted" in texts
        assert str(out) in texts
        assert app._show_done is True
        assert app._pw1v.get() == ""

    def test_colliding_stems_get_distinct_outputs(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        _paths, out = self._batch(app, tmp_path, names=("report.txt", "report.md"))
        app._start()
        assert _pump_until(app, lambda: app._busy is False, 90)
        assert sorted(p.name for p in out.iterdir()) == ["report.qcx", "report_2.qcx"]

    def test_overwriting_existing_outputs_is_challenged(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        conf = _Confirms(False)
        monkeypatch.setattr(enc, "confirm", conf)
        _paths, out = self._batch(app, tmp_path)
        (out / "a.qcx").write_bytes(b"precious")
        app._start()
        app.update()
        assert conf.titles == ["Overwrite?"]
        assert "a.qcx" in conf.message_for("Overwrite?")
        assert (out / "a.qcx").read_bytes() == b"precious"
        assert app._busy is False

    def test_one_bad_file_does_not_stop_the_others(self, mkapp, tmp_path):
        app = mkapp()
        paths, out = self._batch(app, tmp_path)
        gone = str(tmp_path / "vanished.bin")
        bp = {"paths": [paths[0], gone], "outs": [str(out / "a.qcx"), str(out / "v.qcx")],
              "out_dir": str(out), "mode": "single", "pw": PW, "n": 3, "k": 2,
              "embed": False}
        self._arm(app)
        app._run_batch(bp)
        assert _pump_until(app, lambda: app._busy is False, 60)
        assert (out / "a.qcx").exists() and not (out / "v.qcx").exists()
        texts = _widget_texts(app._results)
        assert "✓  1 file encrypted  ·  1 failed" in texts
        assert any("vanished.bin: File not found" in t for t in texts)
        assert bp["pw"] is None

    def test_cancelling_keeps_what_was_already_written(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        paths, out = self._batch(app, tmp_path, names=("a.bin", "b.bin", "c.bin"))
        real = pkg.encrypt_to_qcx
        def _cancel_after_first(*a, **kw):
            res = real(*a, **kw)
            app._cancel_event.set()
            return res
        monkeypatch.setattr(enc.pkg, "encrypt_to_qcx", _cancel_after_first)
        bp = {"paths": paths, "outs": [str(out / f"{i}.qcx") for i in "abc"],
              "out_dir": str(out), "mode": "single", "pw": PW, "n": 3, "k": 2,
              "embed": False}
        self._arm(app)
        app._run_batch(bp)
        assert _pump_until(app, lambda: app._busy is False, 60)
        assert (out / "a.qcx").exists()
        assert not (out / "b.qcx").exists() and not (out / "c.qcx").exists()
        assert app._err.cget("text") == (
            "Cancelled. 1 of 3 files were encrypted; 2 not started, "
            "no partial file was written.")
        assert "✓  1 file encrypted  ·  cancelled" in _widget_texts(app._results)
        assert app._show_done is False

    def test_cancelling_before_the_first_file_writes_nothing(self, mkapp, tmp_path):
        app = mkapp()
        paths, out = self._batch(app, tmp_path)
        app._cancel_event.set()
        self._arm(app)
        app._run_batch({"paths": paths, "outs": [str(out / "a.qcx"), str(out / "b.qcx")],
                        "out_dir": str(out), "mode": "single", "pw": PW, "n": 3, "k": 2,
                        "embed": False})
        assert _pump_until(app, lambda: app._busy is False, 30)
        assert list(out.iterdir()) == []
        assert "0 of 2 files were encrypted" in app._err.cget("text")

    def test_an_embedded_decryptor_is_used_for_every_file(self, mkapp, tmp_path):
        dec = tmp_path / "decryptor"
        dec.write_bytes(b"D" * 512)
        app = mkapp(find_dec=str(dec))
        paths, out = self._batch(app, tmp_path)
        self._arm(app)
        app._run_batch({"paths": paths, "outs": [str(out / "a.qcx"), str(out / "b.qcx")],
                        "out_dir": str(out), "mode": "single", "pw": PW, "n": 3, "k": 2,
                        "embed": True})
        assert _pump_until(app, lambda: app._busy is False, 60)
        assert (out / "a.qcx").read_bytes().startswith(b"D" * 512)
        assert (out / "b.qcx").read_bytes().startswith(b"D" * 512)

    def test_a_split_mode_batch_gives_every_file_its_own_shares(
            self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        paths, out = self._batch(app, tmp_path)
        app._mode.set("shamir")
        app._n.set(3); app._k.set(2)
        app._start()
        assert _pump_until(app, lambda: app._busy is False, 90)
        texts = _widget_texts(app._results)
        assert any("2 files need share distribution" in t for t in texts)
        assert app._shares_pending == {str(out / "a.qcx"), str(out / "b.qcx")}
        cards = [w for w in _all_children(app._results) if isinstance(w, ShareCard)]
        assert len(cards) == 6                      # 3 shares × 2 files

    def test_an_invalid_batch_reports_and_starts_nothing(self, mkapp, tmp_path):
        app = mkapp()
        _paths, out = self._batch(app, tmp_path)
        app._batch_out_var.set(str(tmp_path / "gone"))
        app._start()
        app.update()
        assert app._busy is False
        assert app._err.cget("text").startswith("Output folder does not exist")
        assert list(out.iterdir()) == []

    def test_a_weak_password_is_challenged_for_the_whole_batch(
            self, mkapp, tmp_path, monkeypatch):
        # Forty files at once is the highest-blast-radius operation in the
        # app; it used to be the only one with no weak-password warning.
        app = mkapp()
        _paths, out = self._batch(app, tmp_path)
        app._pw1v.set("aaaaaaaa"); app._pw2v.set("aaaaaaaa")
        conf = _Confirms(False)
        monkeypatch.setattr(enc, "confirm", conf)
        app._start()
        app.update()
        assert conf.titles == ["Weak password"]
        assert list(out.iterdir()) == [] and app._busy is False

    def test_cancelling_inside_a_file_writes_no_partial_output(
            self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        paths, out = self._batch(app, tmp_path)
        real = pkg.encrypt_to_qcx
        def _cancel_mid_file(*a, **kw):
            app._cancel_event.set()      # fires at the first chunk boundary
            return real(*a, **kw)
        monkeypatch.setattr(enc.pkg, "encrypt_to_qcx", _cancel_mid_file)
        self._arm(app)
        app._run_batch({"paths": paths, "outs": [str(out / "a.qcx"), str(out / "b.qcx")],
                        "out_dir": str(out), "mode": "single", "pw": PW, "n": 3, "k": 2,
                        "embed": False})
        assert _pump_until(app, lambda: app._busy is False, 60)
        assert list(out.iterdir()) == []
        assert "0 of 2 files were encrypted" in app._err.cget("text")

    def test_a_summary_row_survives_an_output_that_moved(self, mkapp, tmp_path):
        app = mkapp()
        out = tmp_path / "out"
        out.mkdir()
        app._busy = True
        app._done_batch([(str(out / "moved.qcx"), [], [])], [],
                        {"paths": [None], "out_dir": str(out)})
        texts = _widget_texts(app._results)
        assert "✓  1 file encrypted" in texts
        assert "  ✓  moved.qcx" in texts

    def test_more_than_five_successes_are_summarised(self, mkapp, tmp_path):
        app = mkapp()
        out = tmp_path / "out"
        out.mkdir()
        succeeded = []
        for i in range(7):
            p = out / f"f{i}.qcx"
            p.write_bytes(b"x" * 10)
            succeeded.append((str(p), [], []))
        app._busy = True
        app._done_batch(succeeded, [], {"paths": [None] * 7, "out_dir": str(out)})
        texts = _widget_texts(app._results)
        assert "✓  7 files encrypted" in texts
        assert "  … and 2 more" in texts
        assert "  ✓  f4.qcx" in texts and "  ✓  f5.qcx" not in texts

    def test_retrying_only_re_runs_the_failures(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        paths, out = self._batch(app, tmp_path)
        chosen = str(tmp_path / "chosen")
        os.mkdir(chosen)
        app._batch_out_var.set(chosen)
        started = []
        monkeypatch.setattr(app, "_start", lambda: started.append(list(app._batch_paths)))
        app._retry_failed([paths[1]])
        assert app._batch_paths == [paths[1]]
        assert app._batch_out_var.get() == chosen, "a retry must not move the outputs"
        assert started == [[paths[1]]]

    def test_a_retry_asks_about_unsaved_shares_first(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        paths, _out = self._batch(app, tmp_path)
        boxes = _Boxes(yes=False)
        monkeypatch.setattr(enc, "messagebox", boxes)
        app._shares_pending = {"/somewhere/x.qcx"}
        started = []
        monkeypatch.setattr(app, "_start", lambda: started.append(1))
        app._retry_failed([paths[0]])
        assert started == [] and app._batch_paths == paths
        assert boxes.asked and boxes.asked[0][0] == "Shares not saved"


def _all_children(widget):
    out = []
    for child in widget.winfo_children():
        out.append(child)
        out.extend(_all_children(child))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Shares
# ─────────────────────────────────────────────────────────────────────────────

@requires_tkinter
class TestSuccessCardShares:
    """Contract: a split run shows every share, arms the unsaved-shares guard
    and tells the user what to do next."""

    def _run_split(self, app, tmp_path, monkeypatch, n=3, k=2, on_close=None):
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        src = tmp_path / "in.bin"
        src.write_bytes(b"payload" * 64)
        out = tmp_path / "out.qcx"
        app._on_file(str(src))
        app._out.delete(0, "end")
        app._out.insert(0, str(out))
        app._mode.set("shamir")
        app._n.set(n); app._k.set(k)
        app._start()
        assert _pump_until(app, lambda: app._busy is False and out.exists(), 60)
        return src, out

    def test_a_split_run_shows_one_card_per_share(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        _src, out = self._run_split(app, tmp_path, monkeypatch)
        cards = [w for w in app._results.winfo_children() if isinstance(w, ShareCard)]
        assert len(cards) == 3
        assert len(app._pending_shares) == 3
        assert app._shares_pending == {str(out)}
        texts = _widget_texts(app._results)
        assert "Send each person their share. Any 2 of 3 can unlock the file." in texts
        assert "Save individual files →" in texts and "Save combined file" in texts
        # Any 2 of the 3 codes on screen really do reconstruct the file.
        codes = [c._raw for c in cards]
        restored = tmp_path / "restored"
        restored.mkdir()
        res = pkg.decrypt_qcx(str(out), str(restored), shares=codes[:2])
        assert open(res["output"], "rb").read() == b"payload" * 64

    def test_without_a_launcher_the_checklist_explains_the_long_way_round(
            self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        self._run_split(app, tmp_path, monkeypatch)
        texts = _widget_texts(app._results)
        assert any("Test unlocking from the Home screen" in t for t in texts)
        assert "Test decryption →" not in texts

    def test_with_a_launcher_the_wizard_offers_to_test_the_result(
            self, mkapp, tmp_path, monkeypatch):
        app = mkapp(on_close=lambda: None)
        self._run_split(app, tmp_path, monkeypatch)
        texts = _widget_texts(app._results)
        assert "Test decryption →" in texts
        assert any("Test unlocking it with 2 shares" in t for t in texts)

    def test_copy_all_puts_every_share_on_the_clipboard(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        self._run_split(app, tmp_path, monkeypatch)
        shares = app._pending_shares
        app._copy_all_shares(shares)
        assert app.clipboard_get() == "\n".join(shares)
        assert app._copy_all_btn.cget("text") == "✓ Copied"
        assert "Clipboard clears in" in app._copy_all_clip_lbl.cget("text")

    def test_copy_all_reports_a_clipboard_it_cannot_reach(
            self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        self._run_split(app, tmp_path, monkeypatch)
        def _boom(*a, **k):
            raise tk.TclError("no clipboard")
        monkeypatch.setattr(app, "clipboard_append", _boom)
        app._copy_all_shares(app._pending_shares)
        assert app._copy_all_btn.cget("text") == "⚠ Failed"


@requires_tkinter
class TestSaveIndividualShares:
    """Contract: one file per recipient, 0600, containing that person's share
    and nothing else — and an earlier run's files are never replaced."""

    @pytest.fixture
    def ready(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        src = tmp_path / "will.txt"
        src.write_bytes(b"my last wishes")
        out = tmp_path / "will.qcx"
        app._on_file(str(src))
        app._out.delete(0, "end")
        app._out.insert(0, str(out))
        app._mode.set("shamir")
        app._n.set(3); app._k.set(2)
        app._start()
        assert _pump_until(app, lambda: app._busy is False and out.exists(), 60)
        return app, out, app._pending_shares

    def test_cancelling_the_folder_picker_saves_nothing(self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        dlg = _Dialogs(directory="")
        monkeypatch.setattr(enc, "filedialog", dlg)
        app._save_individual_shares(shares, "will.txt")
        assert [c[0] for c in dlg.calls] == ["askdirectory"]
        assert list(tmp_path.glob("*.share-*")) == []
        assert app._shares_pending == {str(out)}, "the guard stays armed"
        assert "share files saved" not in " ".join(_widget_texts(app._shares_warn))

    def test_each_recipient_gets_only_their_own_share(self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        folder = tmp_path / "to-send"
        folder.mkdir()
        monkeypatch.setattr(enc, "filedialog", _Dialogs(directory=str(folder)))
        app._save_individual_shares(shares, "will.txt",
                                    banner_frame=app._shares_warn)
        files = sorted(folder.iterdir())
        assert [p.name for p in files] == [
            "will.share-1-of-3.txt", "will.share-2-of-3.txt", "will.share-3-of-3.txt"]
        fingerprint = hashlib.sha256(out.read_bytes()[:65536]).hexdigest()[:12]
        for i, path in enumerate(files):
            text = path.read_text()
            assert shares[i] in text
            for other in shares[:i] + shares[i + 1:]:
                assert other not in text
            assert f"QuantaCrypt Share {i + 1} of 3" in text
            assert "Any 2 of 3 shares are needed to decrypt" in text
            assert f"File fingerprint:  {fingerprint}..." in text
            assert "Encrypted file:    will.qcx" in text
            assert "50-word mnemonic" in text
            assert oct(os.stat(path).st_mode & 0o777) == "0o600"
        assert app._shares_pending == set()

    def test_saving_dims_the_cards_and_turns_the_banner_green(
            self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        folder = tmp_path / "to-send"
        folder.mkdir()
        monkeypatch.setattr(enc, "filedialog", _Dialogs(directory=str(folder)))
        app._save_individual_shares(shares, "will.txt", banner_frame=app._shares_warn)
        app.update()
        assert app._shares_warn.cget("highlightbackground") == enc.C["success"]
        assert "✓  3 share files saved" in _widget_texts(app._shares_warn)
        cards = [w for w in app._results.winfo_children() if isinstance(w, ShareCard)]
        assert cards and all(c._copy_btn.cget("text") == "✓ Saved" for c in cards)

    def test_an_earlier_runs_files_are_never_replaced(self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        folder = tmp_path / "to-send"
        folder.mkdir()
        keeper = folder / "will.share-2-of-3.txt"
        keeper.write_text("SOMEONE ELSE'S ONLY KEY")
        monkeypatch.setattr(enc, "filedialog", _Dialogs(directory=str(folder)))
        app._save_individual_shares(shares, "will.txt", banner_frame=app._shares_warn)
        assert keeper.read_text() == "SOMEONE ELSE'S ONLY KEY"
        assert (folder / "will_2.share-2-of-3.txt").exists()
        note = " ".join(_widget_texts(app._shares_warn))
        assert "will_2.share-2-of-3.txt" in note
        assert "The earlier files were left untouched" in note

    def test_a_source_with_no_name_still_produces_a_stem(self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        folder = tmp_path / "to-send"
        folder.mkdir()
        monkeypatch.setattr(enc, "filedialog", _Dialogs(directory=str(folder)))
        app._save_individual_shares(shares, "")
        assert sorted(p.name for p in folder.iterdir())[0] == "shares.share-1-of-3.txt"

    @pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
    def test_a_folder_that_refuses_writes_reports_and_stays_pending(
            self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        folder = tmp_path / "readonly"
        folder.mkdir()
        os.chmod(folder, 0o500)
        boxes = _Boxes()
        monkeypatch.setattr(enc, "messagebox", boxes)
        monkeypatch.setattr(enc, "filedialog", _Dialogs(directory=str(folder)))
        try:
            app._save_individual_shares(shares, "will.txt", banner_frame=app._shares_warn)
        finally:
            os.chmod(folder, 0o700)
        assert boxes.errors and boxes.errors[0][0] == "Save failed"
        assert "Saved 0 of 3 files" in boxes.errors[0][1]
        # Nothing was written, so the shares are still only in this window.
        assert app._shares_pending == {str(out)}
        assert list(folder.iterdir()) == []
        assert app._shares_warn.cget("highlightbackground") == enc.C["warning"]
        assert "share files saved" not in " ".join(_widget_texts(app._shares_warn))

    def test_a_failure_partway_through_says_how_many_were_saved(
            self, ready, tmp_path, monkeypatch):
        """A disk that fills up between recipient 1 and recipient 2.

        The half that made it stays on disk (deleting a recipient's only key
        would be worse), but the guard must stay armed and the banner must not
        claim the set was saved."""
        app, out, shares = ready
        folder = tmp_path / "to-send"
        folder.mkdir()
        real_write = enc.write_new_private_file
        written = []
        def _one_then_no_space(path, text):
            if written:
                raise OSError(28, "No space left on device")
            written.append(path)
            return real_write(path, text)
        monkeypatch.setattr(enc, "write_new_private_file", _one_then_no_space)
        boxes = _Boxes()
        monkeypatch.setattr(enc, "messagebox", boxes)
        monkeypatch.setattr(enc, "filedialog", _Dialogs(directory=str(folder)))
        app._save_individual_shares(shares, "will.txt", banner_frame=app._shares_warn)
        assert boxes.errors and "Saved 1 of 3 files" in boxes.errors[0][1]
        assert "No space left" in boxes.errors[0][1]
        assert [p.name for p in folder.iterdir()] == ["will.share-1-of-3.txt"]
        assert shares[0] in (folder / "will.share-1-of-3.txt").read_text()
        assert app._shares_pending == {str(out)}
        assert "share files saved" not in " ".join(_widget_texts(app._shares_warn))
        cards = [w for w in app._results.winfo_children() if isinstance(w, ShareCard)]
        assert cards and all(c._copy_btn.cget("text") == "Copy" for c in cards), \
            "the cards must stay copyable — two recipients still have no file"

    def test_the_batch_variant_uses_the_qcx_next_to_the_shares(
            self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        folder = tmp_path / "to-send"
        folder.mkdir()
        dlg = _Dialogs(directory=str(folder))
        monkeypatch.setattr(enc, "filedialog", dlg)
        app._shares_pending = {str(out)}
        sec = tk.Frame(app._results, bg=enc.C["surface"])
        sec.pack()
        app._save_individual_shares(shares, "will.qcx", qcx_path=str(out), banner_frame=sec)
        assert app._shares_pending == set()
        assert dlg.calls[0][1]["initialdir"] == str(tmp_path)
        assert "✓  3 share files saved" in _widget_texts(sec)

    def test_an_unreadable_qcx_leaves_the_fingerprint_out(
            self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        folder = tmp_path / "to-send"
        folder.mkdir()
        monkeypatch.setattr(enc, "filedialog", _Dialogs(directory=str(folder)))
        real_open = open
        def _boom(path, *a, **kw):
            if str(path) == str(out):
                raise PermissionError("unreadable")
            return real_open(path, *a, **kw)
        monkeypatch.setattr("builtins.open", _boom)
        app._save_individual_shares(shares, "will.txt")
        monkeypatch.undo()
        text = (folder / "will.share-1-of-3.txt").read_text()
        # The share file is what the recipient needs; a fingerprint that
        # could not be computed must not cost them the share.
        assert shares[0] in text and "File fingerprint" not in text
        assert "Encrypted file:    will.qcx" in text

    def test_a_name_taken_between_the_probe_and_the_write_is_reported(
            self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        folder = tmp_path / "to-send"
        folder.mkdir()
        taken = [folder / f"will.share-{i}-of-3.txt" for i in (1, 2, 3)]
        for path in taken:
            path.write_text("SOMEONE ELSE'S ONLY KEY")
        # Names chosen while they were free, taken by the time of the write:
        # O_EXCL catches the race and every file steps aside.
        monkeypatch.setattr(enc, "_share_file_names",
                            lambda folder, stem, n: ([str(p) for p in taken], False))
        monkeypatch.setattr(enc, "filedialog", _Dialogs(directory=str(folder)))
        app._save_individual_shares(shares, "will.txt", banner_frame=app._shares_warn)
        assert all(p.read_text() == "SOMEONE ELSE'S ONLY KEY" for p in taken)
        assert (folder / "will.share-1-of-3_2.txt").exists()
        note = " ".join(_widget_texts(app._shares_warn))
        assert "will.share-1-of-3_2.txt" in note
        assert "The earlier files were left untouched" in note

    def test_a_missing_qcx_leaves_the_fingerprint_out(self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        folder = tmp_path / "to-send"
        folder.mkdir()
        monkeypatch.setattr(enc, "filedialog", _Dialogs(directory=str(folder)))
        app._out.delete(0, "end")            # no .qcx to fingerprint
        app._save_individual_shares(shares, "will.txt")
        text = (folder / "will.share-1-of-3.txt").read_text()
        assert "File fingerprint" not in text
        assert "keys to the encrypted file" in text


@requires_tkinter
class TestSaveCombinedShares:
    """Contract: the one-file variant carries every share plus the threshold
    and a fingerprint, and equally refuses to clobber an earlier file."""

    @pytest.fixture
    def ready(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        src = tmp_path / "will.txt"
        src.write_bytes(b"my last wishes")
        out = tmp_path / "will.qcx"
        app._on_file(str(src))
        app._out.delete(0, "end")
        app._out.insert(0, str(out))
        app._mode.set("shamir")
        app._n.set(3); app._k.set(2)
        app._start()
        assert _pump_until(app, lambda: app._busy is False and out.exists(), 60)
        return app, out, app._pending_shares

    def test_cancelling_saves_nothing(self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        dlg = _Dialogs(savename="")
        monkeypatch.setattr(enc, "filedialog", dlg)
        app._save_shares(shares, "will.txt")
        assert [c[0] for c in dlg.calls] == ["asksaveasfilename"]
        assert list(tmp_path.glob("*.shares.txt")) == []
        assert app._shares_pending == {str(out)}
        assert "✓  Shares saved" not in _widget_texts(app._shares_warn)

    def test_every_share_and_mnemonic_lands_in_one_private_file(
            self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        target = tmp_path / "will.shares.txt"
        dlg = _Dialogs(savename=str(target))
        monkeypatch.setattr(enc, "filedialog", dlg)
        app._save_shares(shares, "will.txt")
        text = target.read_text()
        assert "Threshold: 2 of 3" in text
        for i, s in enumerate(shares, 1):
            assert f"Share {i}, QCSHARE- code:\n{s}" in text
            assert f"Share {i}, 50-word mnemonic:" in text
        digest = hashlib.sha256(out.read_bytes()[:65536]).hexdigest()[:12]
        assert f"Fingerprint (SHA-256 prefix): {digest}..." in text
        assert oct(os.stat(target).st_mode & 0o777) == "0o600"
        assert app._shares_pending == set()
        assert dlg.calls[0][1]["initialfile"] == "will.shares.txt"
        cards = [w for w in app._results.winfo_children() if isinstance(w, ShareCard)]
        assert all(c._copy_btn.cget("text") == "✓ Saved" for c in cards)
        assert "✓  Shares saved" in _widget_texts(app._shares_warn)

    def test_an_existing_file_is_left_alone(self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        target = tmp_path / "will.shares.txt"
        target.write_text("AN EARLIER RUN'S ONLY KEYS")
        monkeypatch.setattr(enc, "filedialog", _Dialogs(savename=str(target)))
        app._save_shares(shares, "will.txt")
        assert target.read_text() == "AN EARLIER RUN'S ONLY KEYS"
        moved = tmp_path / "will.shares_2.txt"
        assert moved.exists() and shares[0] in moved.read_text()
        assert "The earlier file was left untouched" in " ".join(
            _widget_texts(app._shares_warn))

    def test_a_qcx_that_vanished_is_still_named_in_the_header(
            self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        target = tmp_path / "will.shares.txt"
        monkeypatch.setattr(enc, "filedialog", _Dialogs(savename=str(target)))
        real_open = open
        def _boom(path, *a, **kw):
            if str(path) == str(out):
                raise OSError("unreadable")
            return real_open(path, *a, **kw)
        monkeypatch.setattr("builtins.open", _boom)
        app._save_shares(shares, "will.txt")
        monkeypatch.undo()
        text = target.read_text()
        assert "File:      will.qcx" in text and "Fingerprint" not in text

    @pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
    def test_a_write_failure_reports_and_stays_pending(self, ready, tmp_path, monkeypatch):
        app, out, shares = ready
        folder = tmp_path / "readonly"
        folder.mkdir()
        os.chmod(folder, 0o500)
        boxes = _Boxes()
        monkeypatch.setattr(enc, "messagebox", boxes)
        monkeypatch.setattr(enc, "filedialog",
                            _Dialogs(savename=str(folder / "s.txt")))
        try:
            app._save_shares(shares, "will.txt")
        finally:
            os.chmod(folder, 0o700)
        assert boxes.errors and "have NOT been saved" in boxes.errors[0][1]
        assert app._shares_pending == {str(out)}


@requires_tkinter
class TestSavedBanner:
    """Contract: one recipe for both save paths, and it survives a frame that
    is already gone (the wizard can be reset underneath a save handler)."""

    def test_the_banner_is_rebuilt_green_with_a_reveal_button(self, mkapp, tmp_path):
        app = mkapp()
        target = tk.Frame(app._results, bg=enc.C["surface"],
                          highlightbackground=enc.C["warning"], highlightthickness=1)
        tk.Label(target, text="stale warning").pack()
        target.pack()
        app.update()
        app._show_saved_banner(target, "3 share files saved", "to-send",
                               "a note", str(tmp_path / "x.txt"))
        app.update()
        texts = _widget_texts(target)
        assert "stale warning" not in texts
        assert "✓  3 share files saved" in texts
        assert "to-send" in texts and "a note" in texts
        assert enc.REVEAL_LABEL in texts
        assert target.cget("highlightbackground") == enc.C["success"]

    def test_a_destroyed_frame_is_a_no_op(self, mkapp, tmp_path):
        # Contract: "silently no-ops on a stale/destroyed frame" — NOT RAISING
        # is the documented guarantee (the save handler can outlive the frame
        # it was going to update), so that plus "nothing was drawn anywhere
        # else" is the whole assertion.
        app = mkapp()
        target = tk.Frame(app._results)
        target.destroy()
        app._show_saved_banner(target, "3 share files saved", "w", "n", str(tmp_path))
        assert _alive(app)
        assert app._results.winfo_children() == []
        assert "✓  3 share files saved" not in _widget_texts(app)
        # …and the wizard is still usable afterwards: a live frame still works.
        live = tk.Frame(app._results, bg=enc.C["surface"])
        live.pack()
        app._show_saved_banner(live, "3 share files saved", "w", "n", str(tmp_path))
        assert "✓  3 share files saved" in _widget_texts(live)

    def test_no_frame_at_all_is_a_no_op(self, mkapp, tmp_path):
        # Same contract for the ``target is None`` case (``_save_shares``
        # passes ``getattr(self, "_shares_warn", None)``, which is None until a
        # split run has produced a banner): not raising, and nothing drawn.
        app = mkapp()
        app._show_saved_banner(None, "Shares saved", "w", "n", str(tmp_path))
        assert _alive(app)
        assert app._results.winfo_children() == []
        assert "✓  Shares saved" not in _widget_texts(app)


@requires_tkinter
class TestSharesPendingGuard:
    """Contract: nothing that would discard unsaved shares happens without
    naming the files that become unopenable."""

    def test_an_empty_set_needs_no_prompt(self, mkapp, monkeypatch):
        app = mkapp()
        boxes = _Boxes(yes=False)
        monkeypatch.setattr(enc, "messagebox", boxes)
        assert app._check_shares_saved() is True
        assert boxes.asked == []

    def test_the_single_file_guard_names_the_output(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        boxes = _Boxes(yes=False)
        monkeypatch.setattr(enc, "messagebox", boxes)
        app._out.delete(0, "end")
        app._out.insert(0, str(tmp_path / "will.qcx"))
        app._shares_pending = {"__single__"}
        assert app._check_shares_saved() is False
        assert "will.qcx can never be opened again" in boxes.asked[0][1]

    def test_without_an_output_path_it_says_the_encrypted_file(self, mkapp, monkeypatch):
        app = mkapp()
        boxes = _Boxes(yes=False)
        monkeypatch.setattr(enc, "messagebox", boxes)
        app._shares_pending = {"__single__"}
        app._check_shares_saved()
        assert "the encrypted file can never be opened" in boxes.asked[0][1]

    def test_a_long_batch_list_is_summarised(self, mkapp, monkeypatch):
        app = mkapp()
        boxes = _Boxes(yes=True)
        monkeypatch.setattr(enc, "messagebox", boxes)
        app._shares_pending = {f"/out/f{i}.qcx" for i in range(5)}
        assert app._check_shares_saved() is True
        msg = boxes.asked[0][1]
        assert "f0.qcx, f1.qcx, f2.qcx and 2 more" in msg

    def test_saving_one_file_does_not_disarm_the_rest(
            self, mkapp, tmp_path, monkeypatch, shamir_shares):
        # A batch run gives every file its OWN shares, so the guard is a set of
        # tokens: writing one file's share files may only clear that token.
        # (The old version of this test mutated the set by hand and therefore
        # tested nothing but `set.discard`.)
        _out, codes, _mn = shamir_shares
        app = mkapp()
        a, b = tmp_path / "a.qcx", tmp_path / "b.qcx"
        a.write_bytes(b"encrypted a"); b.write_bytes(b"encrypted b")
        app._shares_pending = {str(a), str(b)}
        app._result_k, app._result_n = 2, 3
        folder = tmp_path / "to-send"
        folder.mkdir()
        monkeypatch.setattr(enc, "filedialog", _Dialogs(directory=str(folder)))
        boxes = _Boxes(yes=False)
        monkeypatch.setattr(enc, "messagebox", boxes)

        app._save_individual_shares(codes, "a.qcx", qcx_path=str(a))

        assert sorted(p.name for p in folder.iterdir()) == [
            "a.share-1-of-3.txt", "a.share-2-of-3.txt", "a.share-3-of-3.txt"]
        assert app._shares_pending == {str(b)}
        assert app._check_shares_saved() is False
        # …and the prompt names only the file that is still at risk.
        assert "b.qcx can never be" in boxes.asked[0][1]
        assert "a.qcx" not in boxes.asked[0][1]

    def test_starting_a_new_run_asks_before_wiping_the_cards(
            self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        boxes = _Boxes(yes=False)
        monkeypatch.setattr(enc, "messagebox", boxes)
        ran = []
        monkeypatch.setattr(app, "_run", lambda p: ran.append(p))
        src = tmp_path / "in.bin"
        src.write_bytes(b"x")
        _fill_single(app, src, tmp_path / "out.qcx")
        app._shares_pending = {"__single__"}
        app._start()
        app.update()
        assert ran == [] and boxes.asked


# ─────────────────────────────────────────────────────────────────────────────
# Leaving, resetting, handing off
# ─────────────────────────────────────────────────────────────────────────────

@requires_tkinter
class TestReset:
    """Contract: "Encrypt another" empties the form but remembers the choices
    that are about how the user works, not about this file."""

    def _used(self, app, tmp_path):
        src = tmp_path / "in.bin"
        src.write_bytes(b"x" * 32)
        _fill_single(app, src, tmp_path / "out.qcx")
        tk.Label(app._results, text="a result card").pack()
        app._toggle_pw(1)
        app._shares_pending = set()
        app._pending_shares = ["QCSHARE-x"]
        return src

    def test_reset_empties_the_form(self, mkapp, tmp_path):
        app = mkapp()
        self._used(app, tmp_path)
        app._reset()
        app.update()
        assert app._path is None and app._batch_paths == []
        assert app._out.get() == "" and app._out_auto is False
        assert app._pw1v.get() == "" and app._pw2v.get() == ""
        assert app._pw1.cget("show") == "•" and app._eye1_btn.cget("text") == "Show"
        assert app._results.winfo_children() == []
        assert app._pending_shares == []
        assert app._wiz._active == 0
        assert app.title() == "QuantaCrypt · Encrypt"
        assert app._src_type.get() == "file"
        assert "Select a file to encrypt" in _widget_texts(app._file_card)
        assert not _packed(app._prog)

    def test_reset_remembers_the_mode_and_the_share_numbers(self, mkapp, tmp_path):
        app = mkapp()
        self._used(app, tmp_path)
        app._mode.set("shamir")
        app._n.set(5); app._k.set(3)
        app._reset()
        assert app._mode.get() == "shamir"
        assert (app._n.get(), app._k.get()) == (5, 3)
        assert app._embed_dec.get() is False

    def test_reset_cancels_a_pending_scroll(self, mkapp, tmp_path):
        app = mkapp()
        app._scroll_job = app.after(10_000, lambda: None)
        job = app._scroll_job
        app._reset()
        assert app._scroll_job is None
        assert job not in app.tk.call("after", "info")

    def test_an_emptied_share_field_no_longer_breaks_encrypt_another(self, mkapp, tmp_path):
        """Was a documented defect: _reset read self._n / self._k directly, so
        an emptied spinbox raised TclError out of "Encrypt another" and left
        the form half-cleared with the previous result card still on screen.
        Run 18 F-204: the read is guarded (see _kn) and happens before
        anything is cleared."""
        app = mkapp()
        self._used(app, tmp_path)
        app._mode.set("shamir")
        app._n.set("")
        app._reset()                                   # no raise
        assert app._path is None and app._pw1v.get() == ""
        assert app._results.winfo_children() == [], "the result card is gone"
        assert app._kn() is None, "an unparseable field is left for the user to fix"
        app._n.set(7); app._k.set(4); app._reset()
        assert app._kn() == (7, 4), "parseable values survive Encrypt another"

    def test_reset_survives_a_scroll_job_that_already_fired(self, mkapp):
        app = mkapp()
        app._scroll_job = "after#already-fired"
        app._reset()
        assert app._scroll_job is None

    def test_keeping_the_batch_keeps_the_folder_and_the_mode(self, mkapp, tmp_path):
        app = mkapp()
        p = tmp_path / "a.bin"
        p.write_bytes(b"x")
        app._set_batch_paths([str(p)])
        app._src_type.set("batch")
        app._build_batch_ui()
        chosen = str(tmp_path / "out")
        os.mkdir(chosen)
        app._batch_out_var.set(chosen)
        app._reset(keep_batch=True)
        app.update()
        assert app._src_type.get() == "batch"
        assert app._batch_out_var.get() == chosen
        assert _packed(app._batch_frame)

    def test_leaving_batch_mode_clears_the_folder(self, mkapp, tmp_path):
        app = mkapp()
        p = tmp_path / "a.bin"
        p.write_bytes(b"x")
        app._set_batch_paths([str(p)])
        app._src_type.set("batch")
        app._build_batch_ui()
        app._reset()
        app.update()
        assert app._batch_out_var.get() == ""
        assert not _packed(app._batch_frame)
        assert _packed(app._file_card)

    def test_refusing_the_share_guard_keeps_the_results(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        self._used(app, tmp_path)
        monkeypatch.setattr(enc, "messagebox", _Boxes(yes=False))
        app._shares_pending = {"__single__"}
        app._reset()
        assert app._path is not None
        assert app._results.winfo_children() != []


@requires_tkinter
class TestClosing:
    """Contract: a half-filled form and unsaved shares both get a prompt; a
    running job gets a "wait" message instead of a closed window."""

    def test_escape_closes_an_untouched_form(self, mkapp):
        closed = []
        app = mkapp(on_close=lambda: closed.append(1))
        _press(app, "<Escape>")
        assert closed == [1] and not _alive(app)

    def test_escape_cancels_a_running_job_instead_of_closing(self, mkapp):
        app = mkapp()
        app._busy = True
        app._cancel_btn.enable(True)
        _press(app, "<Escape>")
        assert _alive(app)
        assert app._cancel_event.is_set()

    def test_a_half_filled_form_asks_first(self, mkapp, tmp_path, monkeypatch):
        app = mkapp(on_close=lambda: None)
        conf = _Confirms(False)
        monkeypatch.setattr(enc, "confirm", conf)
        app._pw1v.set("half typed")
        assert app._has_unsaved_input() is True
        app._on_escape()
        assert _alive(app)
        assert conf.titles == ["Discard this form?"]

    def test_discarding_the_form_closes_it(self, mkapp, tmp_path, monkeypatch):
        closed = []
        app = mkapp(on_close=lambda: closed.append(1))
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        app._pw1v.set("half typed")
        app._on_escape()
        assert closed == [1] and not _alive(app)

    def test_a_produced_result_is_not_treated_as_unsaved_input(self, mkapp, tmp_path):
        app = mkapp()
        app._pw1v.set("typed")
        tk.Label(app._results, text="result").pack()
        # Results have their own guard; the form guard must stand down.
        assert app._has_unsaved_input() is False

    def test_a_selected_file_alone_counts_as_input(self, mkapp, tmp_path):
        app = mkapp()
        src = tmp_path / "a.bin"
        src.write_bytes(b"x")
        app._on_file(str(src))
        assert app._has_unsaved_input() is True

    def test_a_selected_batch_counts_as_input(self, mkapp, tmp_path):
        app = mkapp()
        p = tmp_path / "a.bin"
        p.write_bytes(b"x")
        app._set_batch_paths([str(p)])
        assert app._has_unsaved_input() is True

    def test_closing_while_busy_says_wait(self, mkapp):
        app = mkapp(on_close=lambda: None)
        app._busy = True
        app._close()
        assert _alive(app)
        assert app._err.cget("text") == (
            "Encryption in progress. Please wait until it finishes")

    def test_closing_with_unsaved_shares_asks(self, mkapp, monkeypatch):
        app = mkapp(on_close=lambda: None)
        monkeypatch.setattr(enc, "messagebox", _Boxes(yes=False))
        app._shares_pending = {"__single__"}
        app._close()
        assert _alive(app)

    def test_closing_without_a_launcher_quits_the_app(self, mkapp, tk_root):
        app = mkapp()
        app._close()
        assert not _alive(app) and not _alive(tk_root)


@requires_tkinter
class TestTestDecrypt:
    """Contract: "Test decryption" hands the .qcx to the decryptor and only
    then lets the wizard go."""

    def _split_run(self, app, tmp_path, monkeypatch):
        monkeypatch.setattr(enc, "confirm", _Confirms(True))
        src = tmp_path / "in.bin"
        src.write_bytes(b"payload" * 32)
        out = tmp_path / "out.qcx"
        app._on_file(str(src))
        app._out.delete(0, "end")
        app._out.insert(0, str(out))
        app._mode.set("shamir")
        app._start()
        assert _pump_until(app, lambda: app._busy is False and out.exists(), 60)
        return out

    def test_it_opens_the_decryptor_and_stands_down_the_guard(
            self, mkapp, tmp_path, monkeypatch, tk_root):
        from quantacrypt.ui.shared import RecentFiles
        monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
        app = mkapp(on_close=lambda: None)
        out = self._split_run(app, tmp_path, monkeypatch)
        # The shares are still only on screen, so the guard fires first; the
        # user accepts, because testing the file is the point of this button.
        monkeypatch.setattr(enc, "messagebox", _Boxes(yes=True))
        before = set(tk_root.winfo_children())
        app._test_decrypt(str(out))
        tk_root.update()
        opened = [w for w in tk_root.winfo_children() if w not in before]
        assert len(opened) == 1
        assert "Decrypt" in opened[0].title()
        assert not _alive(app)
        opened[0].destroy()

    def test_a_refused_share_guard_keeps_the_window(self, mkapp, tmp_path, monkeypatch):
        app = mkapp(on_close=lambda: None)
        out = self._split_run(app, tmp_path, monkeypatch)
        monkeypatch.setattr(enc, "messagebox", _Boxes(yes=False))
        app._test_decrypt(str(out))
        assert _alive(app)
        assert app._shares_pending == {str(out)}

    def test_an_unreadable_file_reports_instead_of_closing(self, mkapp, tmp_path, monkeypatch):
        app = mkapp(on_close=lambda: None)
        app._shares_pending = set()
        broken = tmp_path / "broken.qcx"
        broken.write_bytes(b"not a quantacrypt file")
        app._test_decrypt(str(broken))
        assert _alive(app)
        assert app._err.cget("text").startswith("Couldn't open the decryptor: ")
        assert app._err.cget("fg") == enc.C["error"]


@requires_tkinter
class TestRevealUI:
    """Contract: when the OS handler cannot be launched, the wizard says where
    the file is instead of failing silently."""

    def test_a_successful_reveal_says_nothing(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        handled = {"ok": True}
        monkeypatch.setattr(enc, "_reveal",
                            lambda p, open_file=False: handled["ok"])
        app._set_status("a message the reveal must not disturb")
        app._reveal_ui(str(tmp_path / "a.qcx"))
        assert app._err.cget("text") == "a message the reveal must not disturb"
        # Positive control on the same call: only a handler that failed speaks.
        handled["ok"] = False
        app._reveal_ui(str(tmp_path / "a.qcx"))
        assert app._err.cget("text").startswith("Couldn't open the file manager")

    def test_a_failed_reveal_names_the_path(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        monkeypatch.setattr(enc, "_reveal", lambda p, open_file=False: False)
        target = str(tmp_path / "a.qcx")
        app._reveal_ui(target)
        assert app._err.cget("text") == (
            f"Couldn't open the file manager. The file is at {target}")

    def test_a_failed_open_says_open_the_file(self, mkapp, tmp_path, monkeypatch):
        app = mkapp()
        monkeypatch.setattr(enc, "_reveal", lambda p, open_file=False: False)
        target = str(tmp_path / "a.qcx")
        app._reveal_ui(target, open_file=True)
        assert app._err.cget("text") == (
            f"Couldn't open the file. The file is at {target}")
