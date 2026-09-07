"""Behavioural tests for the Tk decryption wizard (``quantacrypt.ui.decryptor``).

Every test here drives the real widgets and asserts on what the wizard ends up
*showing* or *writing* — the rendered label text, the entry contents, the
highlight colour, the file on disk.  Nothing asserts on method source text and
nothing asserts "a mock was called" when the effect itself is observable.

The window is parked off-screen (``-4000-4000``) rather than withdrawn, because
Tk silently drops ``event_generate`` on a non-viewable window and several tests
press real keys.
"""

import io
import json
import os
import struct
import sys
import time as _time
import zipfile

import pytest

from quantacrypt.ui.shared import MOD as _MOD

from quantacrypt.core import crypto as cc
from quantacrypt.core import package as corepkg
from quantacrypt.core.errors import CorruptPayload
from quantacrypt.ui.shared import C, ICON, RecentFiles

from tests.conftest import (
    HAS_TKINTER, MAGIC, _make_qcx, _widget_texts, make_pkg_bytes,
    requires_tkinter,
)

PW = "s3cr3t-testpad"          # the password conftest's qcx_sample was built with


# ── harness ──────────────────────────────────────────────────────────────────

def _pump_until(widget, predicate, timeout=60.0):
    """Run the real Tk main loop until ``predicate`` holds.

    It has to be ``mainloop()`` and not a loop of ``update()`` calls: the
    wizard's workers hand their results back with ``after()`` from a worker
    thread, and Tkinter refuses a cross-thread call unless the main thread is
    genuinely inside the main loop — every hop would otherwise be dropped by
    ``safe_after``'s RuntimeError guard and the window would sit busy forever.
    """
    root = widget._root()
    deadline = _time.monotonic() + timeout
    done = []

    def _check():
        try:
            if predicate():
                done.append(True)
                root.quit()
                return
            if _time.monotonic() > deadline:
                root.quit()
                return
            root.after(20, _check)
        except Exception:
            root.quit()

    root.after(0, _check)
    root.mainloop()
    return bool(done)


def _pump(widget, seconds=0.15):
    """Drain pending ``after`` callbacks for a short while."""
    deadline = _time.monotonic() + seconds
    while _time.monotonic() < deadline:
        try:
            widget.update()
        except Exception:
            return
        _time.sleep(0.005)


@pytest.fixture(scope="module")
def _module_root():
    """One real Tk root for the whole module.

    Same contract as conftest's ``tk_root`` — a real root, mapped so that
    ``event_generate`` is not dropped, parked off-screen — but built once.
    A fresh ``tk.Tk()`` costs ~3.5 s on macOS, which for a file this size is
    more than every assertion in it put together.
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


def _reset_root(root):
    """Put the shared root back into the state a freshly built one is in.

    The root outlives every test in the module, so anything a test leaves on
    it is state the next test inherits: child windows, pending ``after``
    timers, a modal grab, and the keyboard focus.  Three of those need more
    than a single pass:

    * Destroying the children *schedules* new timers rather than clearing
      them — the ``<FocusOut>`` handlers fired by the teardown defer
      ``WordEntry._hfo`` by 150 ms and ``_mc`` by 120 ms — so the drain has to
      keep going until the queue stops refilling instead of cancelling once.
    * ``grab_set`` (the inspect popup, ``shared.confirm``) is application-wide
      state; releasing it before pumping keeps the pump from delivering to a
      window that is on its way out.
    * ``focus_lastfor`` is per-toplevel and survives the widget that held it,
      so the focus is parked back on the root itself.
    """
    for child in root.winfo_children():
        try:
            child.destroy()
        except Exception:
            pass
    try:
        held = root.tk.call("grab", "current")
        if held:
            root.tk.call("grab", "release", held)
    except Exception:
        pass
    for _ in range(10):                    # bounded: a refilling queue must end
        try:
            root.update()
            jobs = root.tk.call("after", "info")
        except Exception:
            break
        if not jobs:
            break
        for job in jobs:
            try:
                root.after_cancel(job)
            except Exception:
                pass
    try:
        root.focus_set()
        root.update_idletasks()
    except Exception:
        pass


@pytest.fixture
def ui_root(_module_root):
    """The shared root, handed over empty and left empty: every child widget,
    every pending ``after`` timer, any modal grab and the keyboard focus are
    reset around each test so nothing leaks into the next one.

    Reset on the way in as well as on the way out: a test whose teardown was
    cut short (a raising callback, a skip mid-teardown) would otherwise hand
    its leftovers to whichever test the shuffle put next."""
    root = _module_root
    _reset_root(root)
    yield root
    _reset_root(root)


def _press(widget, key):
    """Deliver a real key event to ``widget``.

    Key events go to whatever holds the keyboard focus, and on a shared
    display another process can take it back between forcing the focus and
    generating the event — so keep re-taking it until Tk agrees the target is
    focused, and only give up (skip) when the display will not co-operate.
    """
    root = widget._root()
    for _ in range(40):
        try:
            widget.focus_force()
            root.update()
            if root.focus_get() is widget:
                widget.event_generate(key)
                root.update()
                return
        except Exception:
            pass
        _time.sleep(0.05)
    pytest.skip("another application holds this display's keyboard focus")


@pytest.fixture(autouse=True)
def _isolated_recent_files(tmp_path, monkeypatch):
    """No test in this module may reach the user's real recent-files store.

    ``RecentFiles._PATH`` is a class attribute that falls back to the user's
    data directory whenever it is empty, so any DecryptorApp built without
    going through ``_quiet`` reads and writes the real one — a single file
    shared by every test in every module, and by the user's own installation.
    Redirecting it for the whole module makes that impossible to forget;
    ``_quiet`` still points it at its own file inside the same ``tmp_path``.
    """
    monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent-default.json"))


@pytest.fixture(autouse=True)
def _no_worker_outlives_its_test():
    """Never let a decryption thread run on into the next test.

    ``_start``, ``_start_verify`` and ``_extract_folder`` each hand the work
    to a daemon thread that reports back through ``after()``.  A test that
    stops asserting while one is still in flight — a ``_pump_until`` that
    times out, or a deliberate mid-run assertion — would otherwise leave that
    thread alive, and its hop would land in whichever test the shuffle put
    next.  Joining here (bounded; the workers are cancellable and short) is
    what keeps that from depending on the order.
    """
    import threading
    before = set(threading.enumerate())
    yield
    # Matched by target rather than joining every new thread: an unrelated
    # daemon started mid-test (a timeout plugin's timer, a lazy loader) may
    # never exit, and waiting on one would hang the run instead of isolating
    # it.  Thread names carry the target's name — "Thread-3 (_extract_run)".
    workers = ("(_run)", "(_verify_run)", "(_extract_run)")
    deadline = _time.monotonic() + 30.0
    for thread in set(threading.enumerate()) - before:
        if not thread.name.endswith(workers):
            continue
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            break
        thread.join(remaining)


def _quiet(monkeypatch, tmp_path):
    """The decryptor module with OS notifications muted and the recent-files
    store redirected out of the user's real data directory."""
    import quantacrypt.ui.decryptor as dec_mod
    monkeypatch.setattr(RecentFiles, "_PATH", str(tmp_path / "recent.json"))
    monkeypatch.setattr(dec_mod, "notify", lambda *a, **k: None)
    return dec_mod


class _Dialogs:
    """Records what ``confirm``/``alert`` were asked and replays a fixed answer,
    so the modal ``wait_window()`` never blocks the test."""

    def __init__(self, monkeypatch, dec_mod, answer=True):
        self.alerts = []
        self.confirms = []
        self.answer = answer
        monkeypatch.setattr(dec_mod, "alert",
                            lambda parent, title, msg, **kw: self.alerts.append((title, msg)))
        monkeypatch.setattr(dec_mod, "confirm",
                            lambda parent, title, msg, **kw: (
                                self.confirms.append((title, msg)) or self.answer))

    @property
    def alert_titles(self):
        return [t for t, _ in self.alerts]


def _make_app(ui_root, dec_mod, payload=None, qcx_path=None, closed=None):
    app = dec_mod.DecryptorApp(ui_root, payload=payload, qcx_path=qcx_path,
                               on_close=closed if closed is not None else (lambda: None))
    app.geometry("620x780-4000-4000")
    app.update()
    return app


@pytest.fixture
def app_factory(ui_root, tmp_path, monkeypatch):
    """Builds real DecryptorApps and tears every one of them down."""
    dec_mod = _quiet(monkeypatch, tmp_path)
    built = []

    def _factory(**kw):
        app = _make_app(ui_root, dec_mod, **kw)
        built.append(app)
        return app

    _factory.mod = dec_mod
    try:
        yield _factory
    finally:
        for app in built:
            # Ask a worker that is still in flight to stop at its next
            # cancel_check rather than run to completion in the next test's
            # time slice; _no_worker_outlives_its_test then waits for it.
            try:
                app._cancel = True
            except Exception:
                pass
            # src defect (shared.py): SegmentedControl.__init__ trace_add()s
            # the share-mode variable and never trace_remove()s it — there is
            # no <Destroy> handler — so each app leaves a live write trace
            # behind on an interpreter this module shares across ~350 tests,
            # firing _refresh() against a destroyed widget.  Detach what the
            # window should have detached itself.
            try:
                for mode, name in app._imode.trace_info():
                    app._imode.trace_remove(mode, name)
            except Exception:
                pass
            try:
                app.destroy()
            except Exception:
                pass


@pytest.fixture
def loaded_app(app_factory, tmp_path, qcx_sample):
    """A DecryptorApp with a real password-mode .qcx already open."""
    import shutil
    src, meta = qcx_sample
    qcx = tmp_path / "data.qcx"
    shutil.copy(src, qcx)
    app = app_factory(payload={"meta": meta}, qcx_path=str(qcx))
    return app, str(qcx)


@pytest.fixture(scope="session")
def shamir_sample(tmp_path_factory):
    """One real 2-of-3 Shamir .qcx plus its three share codes.  Session-scoped:
    Kyber keygen is the expensive part and every Shamir test wants the same file."""
    d = tmp_path_factory.mktemp("shamir_qcx")
    enc, meta, shares, _fk = _make_qcx(d, b"shamir payload " * 40,
                                       filename="secret.bin", n=3, k=2)
    return str(enc), meta, list(shares)


@pytest.fixture
def shamir_app(app_factory, shamir_sample):
    path, meta, shares = shamir_sample
    app = app_factory(payload={"meta": meta}, qcx_path=path)
    return app, meta, shares


def _mnemonic_for(code, threshold=2):
    return cc.share_to_mnemonic({**cc.decode_share(code), "threshold": threshold})


def _checksum_bad_words(wl):
    """50 real BIP-39 words whose packed checksum does not verify.  Searched
    rather than hard-coded so the phrase can't silently become valid."""
    for i in range(200):
        words = [wl[(i * 7 + j * 131) % len(wl)] for j in range(50)]
        try:
            cc.mnemonic_to_share(" ".join(words))
        except ValueError as exc:
            if "Checksum" in str(exc):
                return words
    raise AssertionError("no checksum-failing phrase found")


# ═════════════════════════════════════════════════════════════════════════════
# Module-level helpers (no display needed)
# ═════════════════════════════════════════════════════════════════════════════


class TestStagesFor:
    """``_stages_for`` picks the dot list for THIS run so no dot is ever
    skipped: a password file never combines shares, a split-key file never
    runs Argon2id, and Verify swaps the payload stage for the chunk check."""

    def test_single_mode_starts_with_the_password_stage(self):
        from quantacrypt.ui.decryptor import _stages_for, STAGES_SINGLE
        stages = _stages_for("single")
        assert [n for n, _, _ in stages] == [n for n, _, _ in STAGES_SINGLE]
        assert stages[0][0] == "Verifying password"

    def test_shamir_mode_starts_with_the_recovery_stage(self):
        from quantacrypt.ui.decryptor import _stages_for
        stages = _stages_for("shamir")
        assert stages[0][0] == "Recovering key"
        assert "Verifying password" not in [n for n, _, _ in stages]

    @pytest.mark.parametrize("mode", ["single", "shamir"])
    def test_verify_replaces_only_the_last_stage(self, mode):
        from quantacrypt.ui.decryptor import _stages_for, STAGE_VERIFY
        plain = _stages_for(mode)
        verify = _stages_for(mode, verify=True)
        assert verify[-1] == STAGE_VERIFY
        assert verify[:-1] == plain[:-1]

    def test_weights_sum_to_one_so_the_bar_reaches_the_end(self):
        from quantacrypt.ui.decryptor import _stages_for
        for mode in ("single", "shamir"):
            assert sum(w for _, w, _ in _stages_for(mode)) == pytest.approx(1.0)

    def test_the_module_constant_is_never_mutated(self):
        """Verify used to overwrite ``STAGES_SINGLE[-1]`` in place, which
        poisoned every later run in the same window."""
        from quantacrypt.ui.decryptor import _stages_for, STAGES_SINGLE
        before = list(STAGES_SINGLE)
        _stages_for("single", verify=True)
        assert STAGES_SINGLE == before

    def test_an_unknown_mode_falls_back_to_the_shamir_list(self):
        from quantacrypt.ui.decryptor import _stages_for, STAGES_SHAMIR
        assert _stages_for(None) == list(STAGES_SHAMIR)


class TestFindStage:
    """``_find_stage`` maps a raw core progress string onto (index, label).
    The raw string must never reach the progress bar."""

    def test_first_stage_matches_its_keyword(self):
        from quantacrypt.ui.decryptor import _find_stage, STAGES_SINGLE
        idx, label = _find_stage("Deriving 512-bit password key (Argon2id)...",
                                 STAGES_SINGLE)
        assert (idx, label) == (0, "Verifying password")

    def test_percentage_is_appended_but_the_raw_wording_is_dropped(self):
        from quantacrypt.ui.decryptor import _find_stage, STAGES_SINGLE
        idx, label = _find_stage("Decrypting payload... 45%", STAGES_SINGLE)
        assert idx == 3
        assert label == "Decrypting file  45%"
        assert "payload" not in label

    @pytest.mark.parametrize("pct", ["0%", "100%"])
    def test_percentage_boundaries_are_carried_through(self, pct):
        from quantacrypt.ui.decryptor import _find_stage, STAGES_SINGLE
        _, label = _find_stage(f"Decrypting payload... {pct}", STAGES_SINGLE)
        assert label.endswith(f"  {pct}")

    def test_shamir_keyword_does_not_match_the_single_list(self):
        from quantacrypt.ui.decryptor import _find_stage, STAGES_SINGLE, STAGES_SHAMIR
        msg = "Combining 2 shares to recover the key..."
        assert _find_stage(msg, STAGES_SINGLE) == (None, None)
        assert _find_stage(msg, STAGES_SHAMIR) == (0, "Recovering key")

    @pytest.mark.parametrize("msg", ["", None, "something else entirely"])
    def test_unrecognised_messages_map_to_nothing(self, msg):
        from quantacrypt.ui.decryptor import _find_stage
        assert _find_stage(msg) == (None, None)

    def test_matching_is_case_insensitive(self):
        from quantacrypt.ui.decryptor import _find_stage, STAGES_SINGLE
        assert _find_stage("RUNNING ARGON2ID NOW", STAGES_SINGLE)[0] == 0

    def test_default_stage_list_is_the_single_mode_one(self):
        from quantacrypt.ui.decryptor import _find_stage
        assert _find_stage("argon2id")[1] == "Verifying password"


class TestZipMemberOk:
    """The zip-slip gate: false for any archive path that could land outside
    the destination directory."""

    @pytest.mark.parametrize("name", [
        "a.txt", "docs/a.txt", "docs/sub/deep.txt", "..foo/x", "a/..b/c",
        "with space/and 'quote'.txt", "unicode/ünïcødé.txt",
    ])
    def test_ordinary_relative_paths_are_allowed(self, name):
        from quantacrypt.ui.decryptor import _zip_member_ok
        assert _zip_member_ok(name) is True

    @pytest.mark.parametrize("name", [
        "", None, "/etc/passwd", "C:/Windows", "c:\\Windows",
        "../escape.txt", "docs/../../escape.txt", "docs\\..\\escape.txt",
        "..",
    ])
    def test_escaping_paths_are_rejected(self, name):
        from quantacrypt.ui.decryptor import _zip_member_ok
        assert _zip_member_ok(name) is False

    def test_a_real_archive_is_screened_member_by_member(self, tmp_path):
        from quantacrypt.ui.decryptor import _zip_member_ok
        z = tmp_path / "mixed.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("ok/a.txt", "a")
            zf.writestr("../evil.txt", "e")
        with zipfile.ZipFile(z) as zf:
            bad = [i.filename for i in zf.infolist() if not _zip_member_ok(i.filename)]
        assert bad == ["../evil.txt"]


class TestOpenFile:
    """``_open_file`` hands the decrypted file to the platform opener and, by
    contract, never raises — a failure to open must not break the result card."""

    def test_macos_uses_open(self, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        calls = []
        monkeypatch.setattr(dec.sys, "platform", "darwin")
        monkeypatch.setattr(dec.subprocess, "run", lambda a, **k: calls.append(a))
        dec._open_file("/tmp/a b.txt")
        assert calls == [["open", "--", "/tmp/a b.txt"]]

    def test_macos_keeps_a_dashed_name_out_of_opens_flags(self, monkeypatch):
        """The recovered original name is the payload's to choose."""
        import quantacrypt.ui.decryptor as dec
        calls = []
        monkeypatch.setattr(dec.sys, "platform", "darwin")
        monkeypatch.setattr(dec.subprocess, "run", lambda a, **k: calls.append(a))
        dec._open_file("-rf.txt")
        assert calls == [["open", "--", "-rf.txt"]]

    def test_linux_hands_xdg_open_an_absolute_path(self, monkeypatch, tmp_path):
        """xdg-open rejects ``--``; an absolute path cannot start with a dash."""
        import quantacrypt.ui.decryptor as dec
        calls = []
        monkeypatch.setattr(dec.sys, "platform", "linux")
        monkeypatch.setattr(dec.subprocess, "run", lambda a, **k: calls.append(a))
        monkeypatch.chdir(tmp_path)
        dec._open_file("-rf.txt")
        assert calls == [["xdg-open", str(tmp_path / "-rf.txt")]]

    def test_windows_uses_startfile(self, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        seen = []
        monkeypatch.setattr(dec.sys, "platform", "win32")
        monkeypatch.setattr(dec.os, "startfile", seen.append, raising=False)
        dec._open_file(r"C:\out\a.txt")
        assert seen == [r"C:\out\a.txt"]

    def test_linux_uses_xdg_open(self, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        calls = []
        monkeypatch.setattr(dec.sys, "platform", "linux")
        monkeypatch.setattr(dec.subprocess, "run", lambda a, **k: calls.append(a))
        dec._open_file("/home/u/a.txt")
        assert calls == [["xdg-open", "/home/u/a.txt"]]

    def test_a_failing_opener_is_swallowed_but_still_attempted(self, monkeypatch):
        # Not-raising IS the contract here: the caller is a button on the
        # success card and the file has already been written.  The opener is
        # still invoked though — the swallow must not degrade into a no-op.
        import quantacrypt.ui.decryptor as dec
        tried = []
        monkeypatch.setattr(dec.sys, "platform", "darwin")

        def _boom(*a, **k):
            tried.append(a[0])
            raise OSError("no launcher")

        monkeypatch.setattr(dec.subprocess, "run", _boom)
        assert dec._open_file("/tmp/x") is None
        assert tried == [["open", "--", "/tmp/x"]]


class TestShareList:
    """``_share_list`` renders share numbers as prose — never a list repr."""

    def test_one(self):
        from quantacrypt.ui.decryptor import _share_list
        assert _share_list([2]) == "Share 2"

    def test_two(self):
        from quantacrypt.ui.decryptor import _share_list
        assert _share_list([1, 3]) == "Shares 1 and 3"

    def test_many(self):
        from quantacrypt.ui.decryptor import _share_list
        assert _share_list([1, 2, 4]) == "Shares 1, 2 and 4"

    def test_numbers_may_arrive_as_ints_or_strings(self):
        from quantacrypt.ui.decryptor import _share_list
        assert _share_list(["1", 2]) == "Shares 1 and 2"

    def test_empty_input_is_not_supported(self):
        # Documents actual behaviour: every call site guards on a non-empty
        # list, so the helper never grew an empty-case branch.
        from quantacrypt.ui.decryptor import _share_list
        with pytest.raises(IndexError):
            _share_list([])


class TestExtractShareCodesDelegation:
    """The UI's ``_extract_share_codes`` is a thin hand-off to core.package so
    "Paste all" and "Load from file…" can't drift from the qc-core service."""

    def test_codes_and_phrases_are_both_found_in_prose(self, shamir_sample):
        from quantacrypt.ui.decryptor import _extract_share_codes
        _, _, shares = shamir_sample
        text = (f"Keep this safe!\n\n{shares[0]}\n\n"
                f"Share two as words:\n{_mnemonic_for(shares[1])}\n")
        found = _extract_share_codes(text)
        assert found[0] == shares[0]
        assert cc.decode_share(found[1])["index"] == cc.decode_share(shares[1])["index"]

    def test_no_shares_in_the_text(self):
        from quantacrypt.ui.decryptor import _extract_share_codes
        assert _extract_share_codes("just a shopping list\nmilk\n") == []

    def test_empty_text(self):
        from quantacrypt.ui.decryptor import _extract_share_codes
        assert _extract_share_codes("") == []


class TestGetWl:
    """``get_wl`` memoises the 2048-word BIP-39 list — loading it per keystroke
    would make the 50-word grid unusable."""

    def test_returns_the_bip39_list_and_caches_it(self):
        from quantacrypt.ui.decryptor import get_wl
        wl = get_wl()
        assert len(wl) == 2048
        assert wl[0] == "abandon" and "zoo" in wl
        assert get_wl() is wl


class TestProtectionLabel:
    """Plain-language "how is this protected" copy shared by both cards."""

    def test_password_mode(self):
        from quantacrypt.ui.decryptor import _protection_label
        assert _protection_label({"mode": "single"}) == "A password"

    def test_shamir_mode_names_the_threshold(self):
        from quantacrypt.ui.decryptor import _protection_label
        assert _protection_label({"mode": "shamir", "threshold": 2, "total": 5}) == \
            "A split key. Any 2 of 5 shares unlock it"

    def test_shamir_without_parameters_says_so_rather_than_crashing(self):
        from quantacrypt.ui.decryptor import _protection_label
        assert _protection_label({"mode": "shamir"}) == \
            "A split key. Any ? of ? shares unlock it"

    def test_unknown_mode_is_echoed(self):
        from quantacrypt.ui.decryptor import _protection_label
        assert _protection_label({"mode": "quantum"}) == "quantum"

    def test_missing_mode(self):
        from quantacrypt.ui.decryptor import _protection_label
        assert _protection_label({}) == "?"


# ═════════════════════════════════════════════════════════════════════════════
# Cards and tooltips
# ═════════════════════════════════════════════════════════════════════════════


@requires_tkinter
class TestFileInfoCard:
    """The metadata card renders only what is actually known: the filename is
    inside the encrypted payload, so before decryption it must say so."""

    def test_filename_is_hidden_until_decryption(self, ui_root):
        from quantacrypt.ui.decryptor import FileInfoCard
        card = FileInfoCard(ui_root, {"mode": "single"}, None)
        texts = _widget_texts(card)
        assert "Hidden; shown after decryption" in texts
        assert "A password" in texts

    def test_recovered_filename_replaces_the_placeholder(self, ui_root):
        from quantacrypt.ui.decryptor import FileInfoCard
        card = FileInfoCard(ui_root, {"mode": "single"}, "report.pdf")
        texts = _widget_texts(card)
        assert "report.pdf" in texts
        assert "Hidden; shown after decryption" not in texts

    def test_shamir_card_names_the_threshold(self, ui_root):
        from quantacrypt.ui.decryptor import FileInfoCard
        card = FileInfoCard(ui_root, {"mode": "shamir", "threshold": 3, "total": 5}, None)
        assert "A split key. Any 3 of 5 shares unlock it" in _widget_texts(card)

    def test_size_and_date_rows_appear_only_once_known(self, ui_root):
        from quantacrypt.ui.decryptor import FileInfoCard
        bare = _widget_texts(FileInfoCard(ui_root, {"mode": "single"}, "a", sz=0, ts=0))
        assert "Original size" not in bare and "Encrypted on" not in bare

        full = _widget_texts(FileInfoCard(ui_root, {"mode": "single"}, "a",
                                          sz=2048, ts=1_600_000_000))
        assert "Original size" in full and "2.0 KB" in full
        assert "Encrypted on" in full
        stamp = _time.strftime("%Y-%m-%d %H:%M", _time.localtime(1_600_000_000))
        assert stamp in full

    def test_an_unrenderable_timestamp_drops_the_row_instead_of_crashing(self, ui_root):
        from quantacrypt.ui.decryptor import FileInfoCard
        texts = _widget_texts(FileInfoCard(ui_root, {"mode": "single"}, "a",
                                           sz=10, ts=10 ** 20))
        assert "Original size" in texts        # everything before it survived
        assert "Encrypted on" not in texts


@requires_tkinter
class TestTooltip:
    """Hover help for the Verify button.  It is deliberately duplicated as a
    visible caption, so the tooltip itself only has to be harmless."""

    def test_hover_shows_the_text_once_and_leave_removes_it(self, ui_root):
        import tkinter as tk
        from quantacrypt.ui.decryptor import _Tooltip
        lbl = tk.Label(ui_root, text="hover me")
        lbl.pack()
        ui_root.update()
        tip = _Tooltip(lbl, "explains the button")

        tip._show()
        assert tip._tip is not None
        assert _widget_texts(tip._tip) == ["explains the button"]

        first = tip._tip
        tip._show()                       # a second Enter must not stack windows
        assert tip._tip is first

        tip._hide()
        assert tip._tip is None
        assert not first.winfo_exists()

    def test_hide_drops_the_reference_so_a_later_hover_works_again(self, ui_root):
        """``_hide`` runs from <Leave>, which can arrive after the tip window
        was already reclaimed.  Swallowing that is only half the job: it also
        has to drop its own reference, or the next <Enter> finds ``_tip``
        truthy, returns early, and hover help is dead for the rest of the run.
        """
        import tkinter as tk
        from quantacrypt.ui.decryptor import _Tooltip
        lbl = tk.Label(ui_root, text="hover me")
        lbl.pack()
        ui_root.update()
        tip = _Tooltip(lbl, "explains it")

        tip._show()
        first = tip._tip
        first.destroy()                   # the window went away under us
        tip._hide()
        assert tip._tip is None

        tip._show()                       # …so hovering again still works
        assert tip._tip is not None and tip._tip is not first
        assert _widget_texts(tip._tip) == ["explains it"]
        tip._hide()
        assert tip._tip is None
        tip._hide()                       # nothing to hide → still None
        assert tip._tip is None

    def test_a_destroyed_widget_leaves_no_tip_behind(self, ui_root):
        """Placement reads ``winfo_rootx`` on the widget, which raises once it
        is gone — the half-built tip must be abandoned, not leaked as an
        orphan toplevel stuck on the screen."""
        import tkinter as tk
        from quantacrypt.ui.decryptor import _Tooltip
        lbl = tk.Label(ui_root, text="gone")
        lbl.pack()
        ui_root.update()
        tip = _Tooltip(lbl, "t")
        lbl.destroy()
        before = len(ui_root.winfo_children())
        with pytest.raises(tk.TclError):
            lbl.winfo_rootx()             # exactly what _show has to survive
        tip._show()
        assert tip._tip is None
        assert len(ui_root.winfo_children()) == before, "no orphan window"


# ═════════════════════════════════════════════════════════════════════════════
# WordEntry — one cell of the 50-word grid
# ═════════════════════════════════════════════════════════════════════════════


@requires_tkinter
class TestWordEntry:
    """One autocompleting BIP-39 cell: border colour states, the dropdown
    lifecycle, and the keys that move between cells."""

    @pytest.fixture
    def cell(self, ui_root):
        import tkinter as tk
        from quantacrypt.ui.decryptor import WordEntry, get_wl
        frame = tk.Frame(ui_root)
        frame.pack(fill="both", expand=True)
        confirmed, done = [], []
        w = WordEntry(frame, 1, get_wl(),
                      on_confirm=confirmed.append, on_done=lambda: done.append(1))
        w.pack()
        ui_root.update()
        w.confirmed, w.done = confirmed, done
        yield w
        try:
            w._close()
            frame.destroy()
        except Exception:
            pass

    def _border(self, w):
        return str(w.cget("highlightbackground"))

    def test_get_normalises_case_and_whitespace(self, cell):
        cell._v.set("  ABANDON  ")
        assert cell.get() == "abandon"
        assert cell.valid() is True

    def test_set_marks_a_known_word_green(self, cell):
        cell.set("Zoo")
        assert cell.get() == "zoo"
        assert self._border(cell) == C["success"]

    def test_set_marks_an_unknown_word_red(self, cell):
        cell.set("qqqqq")
        assert cell.valid() is False
        assert self._border(cell) == C["error"]

    def test_clearing_returns_to_the_neutral_border(self, cell):
        cell.set("abandon")
        cell.set("")
        assert self._border(cell) == C["border"]
        assert cell._open is False

    def test_a_prefix_opens_the_dropdown_with_the_matches(self, cell):
        cell._v.set("aban")
        assert cell._open is True
        # "aban" is the prefix of exactly one BIP-39 word, so the list is
        # pinned in full rather than by its first row.
        assert cell._lb.get(0, "end") == ("abandon",)
        assert self._border(cell) == C["accent_text"]

    def test_an_exact_unique_word_closes_the_dropdown(self, cell):
        cell._v.set("zoo")
        assert cell._open is False
        assert self._border(cell) == C["success"]

    def test_an_exact_word_that_is_still_a_prefix_keeps_the_list_open(self, cell):
        # "act" is a word AND the prefix of "action"/"actor" — the user still
        # needs to see the alternatives.
        cell._v.set("act")
        assert cell._open is True
        assert self._border(cell) == C["success"]

    def test_no_match_closes_the_dropdown_and_goes_red(self, cell):
        cell._v.set("aban")
        cell._v.set("xyzzy")
        assert cell._open is False
        assert self._border(cell) == C["error"]

    def test_the_dropdown_is_capped_at_thirty_rows(self, cell):
        cell._v.set("a")                       # ~130 words start with "a"
        assert cell._lb.size() == 30
        assert int(cell._lb.cget("height")) == cell.MAX_DROP

    def test_the_dropdown_flips_above_when_it_would_fall_off_the_screen(self, cell,
                                                                       monkeypatch):
        """Positions are read from the geometry string the code requests: a
        window manager is free to move a real toplevel afterwards."""
        import tkinter as tk
        placed = []
        original = tk.Toplevel.wm_geometry

        def _record(self, newGeometry=None):
            if newGeometry:
                placed.append(newGeometry)
            return original(self, newGeometry)

        monkeypatch.setattr(tk.Toplevel, "wm_geometry", _record)

        # Anchor the window somewhere known first. Comparing two absolute y
        # values collapses when the window happens to sit at the top of the
        # screen — which it does under a bare window manager, so this passed
        # on macOS and failed on Linux CI. Asserting against the entry's own
        # position states the actual contract and does not care where the
        # window manager put things.
        top = cell.winfo_toplevel()
        top.wm_geometry("+200+200")
        top.update_idletasks()
        entry_top = cell.winfo_rooty()

        cell._v.set("aban")
        below = int(placed[-1].split("+")[2])
        assert below >= entry_top, "with room underneath the list hangs below the entry"
        cell._close()

        monkeypatch.setattr(tk.Misc, "winfo_screenheight", lambda self: 1)
        cell._v.set("aban")
        above = int(placed[-1].split("+")[2])
        assert above < below, "no room underneath → the list sits above the entry"

    def test_escape_closes_the_dropdown_and_swallows_the_event(self, cell):
        cell._v.set("aban")
        assert cell._esc(None) == "break"       # must not reach the window's Esc
        assert cell._open is False
        assert cell._esc(None) is None          # nothing open → let it propagate

    def test_down_opens_the_list_and_selects_the_first_row(self, cell):
        cell._v.set("aban")
        cell._close()
        cell._v.set("aban")
        assert cell._dn(None) == "break"
        assert cell._lb.curselection()

    def test_down_on_an_empty_cell_does_nothing(self, cell):
        assert cell._dn(None) == "break"
        assert cell._open is False

    def test_up_moves_into_the_open_list_and_is_always_swallowed(self, cell,
                                                                  ui_root):
        cell._e.focus_set()
        ui_root.update()
        cell._v.set("aban")
        assert cell._up(None) == "break"
        assert cell._lb.winfo_toplevel().focus_lastfor() is cell._lb, \
            "Up hands the keyboard to the completion list"

        cell._close()
        cell._e.focus_set()
        ui_root.update()
        assert cell._up(None) == "break", "swallowed with nothing open too"
        assert cell.winfo_toplevel().focus_lastfor() is cell._e, \
            "…and the cursor stays in the cell"

    def test_return_picks_the_highlighted_word(self, cell):
        cell._v.set("aban")
        cell._lb.selection_set(0)
        first = cell._lb.get(0)
        assert cell._ret(None) == "break"
        assert cell.get() == first
        assert cell.confirmed == [first]
        assert cell._open is False

    def test_return_on_a_complete_word_moves_on(self, cell):
        cell.set("zoo")
        cell._ret(None)
        assert cell.done == [1]

    def test_return_on_an_invalid_word_stays_put(self, cell):
        cell.set("qqqqq")
        cell._ret(None)
        assert cell.done == []

    def test_tab_takes_the_selection_when_there_is_one(self, cell):
        cell._v.set("aban")
        cell._lb.selection_set(0)
        assert cell._tab(None) == "break"
        assert cell.get() == "abandon"

    def test_tab_takes_the_top_row_when_nothing_is_selected(self, cell):
        cell._v.set("zoo")
        cell._show(["zoo", "zone"])
        assert cell._tab(None) == "break"
        assert cell.get() == "zoo"

    def test_tab_with_no_dropdown_advances(self, cell):
        cell.set("zoo")
        cell._close()
        assert cell._tab(None) == "break"
        assert cell.done == [1]

    def test_space_accepts_the_top_row(self, cell):
        cell._v.set("aban")
        assert cell._spc(None) == "break"
        assert cell.get() == "abandon"

    def test_space_on_a_complete_word_advances(self, cell):
        cell.set("zoo")
        cell._close()
        assert cell._spc(None) == "break"
        assert cell.done == [1]

    def test_space_on_an_incomplete_word_is_left_to_tk(self, cell):
        cell.set("qqq")
        cell._close()
        assert cell._spc(None) is None

    def test_show_with_no_matches_closes_instead_of_opening_an_empty_list(self, cell):
        cell._v.set("aban")
        dd = cell._dd
        assert cell._open is True and dd is not None
        cell._show([])
        assert cell._open is False and cell._dd is None
        assert not dd.winfo_exists(), "the empty list is torn down, not shown"

    def test_closing_a_dropdown_whose_window_already_went_away(self, cell):
        """BUG (documented, not fixed here): ``_close`` guards ``destroy()``
        but not the ``withdraw()`` above it, so a dropdown Tk has already
        reclaimed raises instead of closing quietly.  ``_mc`` reaches this
        from its own except-branch 120 ms after a teardown."""
        import tkinter as tk
        cell._v.set("aban")
        cell._dd.destroy()          # the window went away under us
        with pytest.raises(tk.TclError):
            cell._close()

    def test_close_without_destroying_keeps_the_toplevel_for_reuse(self, cell):
        cell._v.set("aban")
        dd = cell._dd
        cell._close(dest=False)
        assert cell._open is False
        assert cell._dd is dd and dd.winfo_exists()

    def test_focus_in_reopens_the_list_for_a_partial_word(self, cell):
        cell._v.set("aban")
        cell._close()
        cell._fin(None)
        assert cell._open is True

    def test_focus_in_on_a_complete_word_opens_nothing(self, cell):
        cell.set("zoo")
        cell._close()
        cell._fin(None)
        assert cell._open is False

    def test_delayed_focus_out_on_a_destroyed_cell_is_harmless(self, cell):
        """``_fout`` defers 150 ms, so ``_hfo`` routinely wakes to a cell that
        is already gone.  The early return is load-bearing: the work it skips
        raises on a dead widget."""
        import tkinter as tk
        cell.set("zoo")
        cell.destroy()
        with pytest.raises(tk.TclError):
            cell._border()                # the very first thing _hfo would do
        assert cell._hfo() is None

    def test_focus_out_restores_the_border_and_closes(self, cell):
        cell.set("qqqq")
        cell._v.set("aban")
        cell._hfo()
        assert self._border(cell) == C["error"]
        assert cell._open is False

    def test_listbox_click_selects_the_word(self, cell):
        cell._v.set("aban")
        cell._lb.selection_set(0)
        cell._lbpick(None)
        assert cell.get() == "abandon"

    def test_listbox_click_without_a_selection_changes_nothing(self, cell):
        cell._v.set("aban")
        cell._lb.selection_clear(0, "end")
        cell._lbpick(None)
        assert cell.get() == "aban"

    def test_listbox_tab_selects_and_is_swallowed(self, cell):
        cell._v.set("aban")
        cell._lb.selection_set(0)
        assert cell._lbtab(None) == "break"
        assert cell.get() == "abandon"

    def test_listbox_escape_closes_and_is_swallowed(self, cell):
        cell._v.set("aban")
        assert cell._lbesc(None) == "break"
        assert cell._open is False

    def test_escape_in_the_list_closes_it_even_if_the_cell_entry_has_gone(self,
                                                                          cell):
        """Escape hands focus back to the entry, which a racing teardown may
        have taken away.  The list must still close and the key must still be
        swallowed — otherwise Escape reaches the window binding and throws
        away every word typed so far."""
        import tkinter as tk
        cell._v.set("aban")
        dd = cell._dd
        cell._e.destroy()
        with pytest.raises(tk.TclError):
            cell._e.focus_force()          # what _lbesc has to survive
        assert cell._lbesc(None) == "break"
        assert cell._open is False and cell._dd is None
        assert not dd.winfo_exists()

    def test_mouse_check_closes_when_focus_left_the_widget(self, cell):
        cell._v.set("aban")
        cell._mc()
        assert cell._open is False

    def test_next_focuses_the_chained_cell(self, ui_root, cell):
        from quantacrypt.ui.decryptor import WordEntry, get_wl
        nxt = WordEntry(cell.master, 2, get_wl())
        nxt.pack()
        ui_root.update()
        cell._nxt = nxt
        cell.set("zoo")
        cell._ret(None)
        assert cell.done == []             # the chain wins over the done callback
        nxt.destroy()

    def test_set_enabled_toggles_the_entry_state(self, cell):
        cell.set_enabled(False)
        assert str(cell._e.cget("state")) == "disabled"
        cell.set_enabled(True)
        assert str(cell._e.cget("state")) == "normal"

    def test_both_focus_helpers_land_the_cursor_in_the_entry(self, ui_root, cell):
        import tkinter as tk
        other = tk.Entry(cell.master)
        other.pack()
        ui_root.update()

        other.focus_set()
        ui_root.update()
        assert cell.winfo_toplevel().focus_lastfor() is other   # precondition

        cell.focus()
        ui_root.update()
        assert cell.winfo_toplevel().focus_lastfor() is cell._e

        other.focus_set()
        ui_root.update()
        cell.focus_force()
        ui_root.update()
        assert cell.winfo_toplevel().focus_lastfor() is cell._e
        other.destroy()

    def test_leaving_the_field_closes_the_list_after_the_grace_period(self, cell):
        """The close is deferred 150 ms so a click *into* the list is not read
        as leaving the field."""
        cell._v.set("aban")
        cell._fout(None)
        assert cell._open is True, "still open during the grace period"
        assert _pump_until(cell, lambda: cell._open is False, timeout=3.0)

    def test_escape_is_wired_to_the_entry(self, cell):
        cell._v.set("aban")
        _press(cell._e, "<Escape>")
        assert cell._open is False


# ═════════════════════════════════════════════════════════════════════════════
# MnemonicShareInput — one collapsible 50-word share panel
# ═════════════════════════════════════════════════════════════════════════════


@requires_tkinter
class TestMnemonicShareInput:
    """The collapsible share panel: counter, progress rule, expand/collapse,
    bulk paste and the enable/disable used while decryption runs."""

    @pytest.fixture
    def panel(self, ui_root):
        import tkinter as tk
        from quantacrypt.ui.decryptor import MnemonicShareInput, get_wl
        frame = tk.Frame(ui_root)
        frame.pack(fill="both", expand=True)
        changes = []
        p = MnemonicShareInput(frame, 1, get_wl(), on_change=lambda: changes.append(1))
        p.pack(fill="x")
        ui_root.update()
        p.changes = changes
        yield p
        try:
            frame.destroy()
        except Exception:
            pass

    def _words(self, shamir_sample):
        _, _, shares = shamir_sample
        return _mnemonic_for(shares[0]).split()

    def test_a_fresh_panel_is_empty(self, panel):
        assert panel.valid_count() == 0
        assert panel.is_complete() is False
        assert panel.has_input() is False
        assert panel._count.cget("text") == "0 / 50 words"
        assert str(panel._count.cget("fg")) == C["text3"]

    def test_one_word_registers_in_the_counter(self, panel, ui_root):
        panel._cells[0].set("zoo")
        panel._upd()
        assert panel.valid_count() == 1
        assert panel.has_input() is True
        assert panel._count.cget("text") == "1 / 50 words"
        assert str(panel._count.cget("fg")) == C["warning"]

    def test_forty_nine_words_is_still_incomplete(self, panel, shamir_sample):
        words = self._words(shamir_sample)
        panel.set_words(words[:49])
        assert panel.valid_count() == 49
        assert panel.is_complete() is False
        assert panel._count.cget("text") == "49 / 50 words"

    def test_a_full_phrase_completes_the_panel(self, panel, shamir_sample):
        words = self._words(shamir_sample)
        panel.set_words(words)
        assert panel.is_complete() is True
        assert panel.get_mnemonic().split() == [w.lower() for w in words]
        assert panel._count.cget("text") == f"50 / 50 words  {ICON['ok']}"
        assert str(panel._count.cget("fg")) == C["success"]

    def test_set_words_stops_at_the_fiftieth_word(self, panel, shamir_sample):
        """The grid is fixed at 50 cells; a 51-word paste must fill it exactly
        and drop the extra rather than raising or wrapping."""
        words = self._words(shamir_sample)
        panel.set_words(words + ["zoo"])
        assert len(panel._cells) == 50
        assert panel.is_complete() is True
        assert panel.get_mnemonic().split() == [w.lower() for w in words]

    def test_clear_empties_every_cell(self, panel, shamir_sample):
        panel.set_words(self._words(shamir_sample))
        panel.clear()
        assert panel.valid_count() == 0 and panel.has_input() is False
        assert panel.get_mnemonic().strip() == ""

    def test_the_progress_rule_tracks_the_word_count(self, panel, shamir_sample,
                                                     ui_root):
        panel._draw_pbar(200)
        assert panel._pbar.find_all() == ()        # nothing filled at zero

        words = self._words(shamir_sample)
        panel.set_words(words[:25])
        panel._draw_pbar(200)
        assert len(panel._pbar.find_all()) == 1
        assert str(panel._pbar.itemcget(panel._pbar.find_all()[0], "fill")) == C["warning"]

        panel.set_words(words)
        panel._draw_pbar(200)
        assert str(panel._pbar.itemcget(panel._pbar.find_all()[0], "fill")) == C["success"]

    def test_the_rule_is_not_drawn_before_the_canvas_has_a_width(self, panel,
                                                                 shamir_sample):
        """Zero width is the pre-layout state, not "nothing to fill" — a
        complete 50 words must still put nothing on a canvas with no width."""
        panel.set_words(self._words(shamir_sample))
        assert panel.valid_count() == 50
        panel._pbar.delete("all")
        panel._draw_pbar(0)
        assert panel._pbar.find_all() == ()
        panel._draw_pbar(200)
        assert len(panel._pbar.find_all()) == 1, "…and it fills once it has one"

    def test_on_change_fires_only_when_the_count_moves(self, panel):
        panel.changes.clear()
        panel._cells[0].set("zoo")
        panel._upd()
        assert len(panel.changes) == 1
        panel._upd()                        # same count → no second notification
        assert len(panel.changes) == 1

    def test_toggle_hides_and_restores_the_grid(self, panel):
        assert panel._grid_frame.winfo_manager() == "pack"
        panel.toggle()
        assert panel._expanded is False
        assert panel._grid_frame.winfo_manager() == ""
        assert panel._chevron.cget("text") == ICON["chevron_closed"]
        panel.toggle()
        assert panel._grid_frame.winfo_manager() == "pack"
        assert panel._chevron.cget("text") == ICON["chevron_open"]

    def test_expand_and_collapse_are_idempotent(self, panel):
        panel.expand()
        assert panel._expanded is True
        panel.collapse(); panel.collapse()
        assert panel._expanded is False
        panel.expand()
        assert panel._expanded is True

    def test_focus_expands_first_so_the_cell_is_visible(self, panel, ui_root):
        panel.collapse()
        panel.focus()
        ui_root.update()
        assert panel._expanded is True

    def test_a_collapsed_panel_starts_with_the_grid_hidden(self, ui_root):
        import tkinter as tk
        from quantacrypt.ui.decryptor import MnemonicShareInput, get_wl
        frame = tk.Frame(ui_root); frame.pack()
        p = MnemonicShareInput(frame, 2, get_wl(), start_expanded=False)
        p.pack(); ui_root.update()
        assert p._grid_frame.winfo_manager() == ""
        assert p._chevron.cget("text") == ICON["chevron_closed"]
        frame.destroy()

    @pytest.mark.parametrize("target", ["header", "chevron"])
    def test_clicking_the_header_row_toggles_the_grid(self, panel, target):
        widget = panel._hdr if target == "header" else panel._chevron
        widget.event_generate("<Button-1>")
        panel.update()
        assert panel._grid_frame.winfo_manager() == ""
        widget.event_generate("<Button-1>")
        panel.update()
        assert panel._grid_frame.winfo_manager() == "pack"

    @pytest.mark.parametrize("key", ["<Return>", "<space>"])
    def test_the_header_is_operable_from_the_keyboard(self, panel, key):
        """The header is in the Tab order, so it has to answer Return/space —
        a mouse-only disclosure control is unreachable without one."""
        _press(panel._hdr, key)
        assert panel._expanded is False

    def test_the_header_shows_a_focus_ring(self, panel):
        panel._hdr.event_generate("<FocusIn>")
        panel.update()
        assert int(panel._hdr.cget("highlightthickness")) == 2
        assert str(panel._hdr.cget("highlightbackground")) == C["accent_text"]
        panel._hdr.event_generate("<FocusOut>")
        panel.update()
        assert int(panel._hdr.cget("highlightthickness")) == 1
        assert str(panel._hdr.cget("highlightbackground")) == C["border"]

    def test_set_enabled_freezes_the_cells_and_the_buttons(self, panel):
        panel.set_enabled(False)
        assert all(str(c._e.cget("state")) == "disabled" for c in panel._cells)
        assert panel._paste_btn._enabled is False and panel._clear_btn._enabled is False
        assert int(panel._hdr.cget("takefocus")) == 0
        panel.set_enabled(True)
        assert all(str(c._e.cget("state")) == "normal" for c in panel._cells)
        assert int(panel._hdr.cget("takefocus")) == 1

    def test_edits_schedule_exactly_one_refresh_per_burst(self, panel, shamir_sample,
                                                          ui_root):
        """set_words fires 50 write traces; polling on each would be 50 full
        counter rebuilds."""
        panel._upd_job = None
        panel._cells[0]._v.set("zoo")
        assert panel._upd_job is not None
        job = panel._upd_job
        panel._cells[1]._v.set("zone")
        assert panel._upd_job is job          # coalesced, not queued twice
        ui_root.update()
        assert panel._upd_job is None
        assert panel._count.cget("text") == "2 / 50 words"

    def test_refresh_on_a_destroyed_panel_clears_its_job_and_stays_quiet(self,
                                                                          panel):
        """The refresh is queued with ``after_idle``, so it routinely fires
        after the window has gone.  It must drop its pending-job handle first
        — otherwise ``_schedule_upd`` would never queue another — and only
        then return, because the widget writes it skips would raise."""
        import tkinter as tk
        panel.destroy()
        assert panel.winfo_exists() == 0
        panel._upd_job = "a-stale-job-id"
        with pytest.raises(tk.TclError):
            panel._count.config(text="x")     # the write _upd would otherwise do
        assert panel._upd() is None
        assert panel._upd_job is None

    # ── Paste ────────────────────────────────────────────────────────────────

    def test_paste_fills_the_grid_from_a_valid_phrase(self, panel, shamir_sample,
                                                      monkeypatch):
        import quantacrypt.ui.decryptor as dec
        _Dialogs(monkeypatch, dec)
        phrase = " ".join(self._words(shamir_sample))
        monkeypatch.setattr(type(panel), "clipboard_get", lambda self: phrase,
                            raising=False)
        panel._paste()
        assert panel.is_complete() is True

    def test_paste_with_an_empty_clipboard_says_so(self, panel, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        d = _Dialogs(monkeypatch, dec)

        def _boom(self):
            raise Exception("CLIPBOARD_EMPTY")

        monkeypatch.setattr(type(panel), "clipboard_get", _boom, raising=False)
        panel._paste()
        assert d.alert_titles == ["Nothing to paste"]
        assert panel.has_input() is False

    def test_pasting_a_code_share_points_at_the_other_tab(self, panel, shamir_sample,
                                                          monkeypatch):
        import quantacrypt.ui.decryptor as dec
        d = _Dialogs(monkeypatch, dec)
        _, _, shares = shamir_sample
        monkeypatch.setattr(type(panel), "clipboard_get", lambda self: shares[0],
                            raising=False)
        panel._paste()
        assert d.alert_titles == ["That's a code share"]
        assert panel.has_input() is False

    @pytest.mark.parametrize("count", [0, 1, 49, 51])
    def test_paste_rejects_the_wrong_word_count(self, panel, count, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        d = _Dialogs(monkeypatch, dec)
        text = " ".join(["zoo"] * count)
        monkeypatch.setattr(type(panel), "clipboard_get", lambda self: text,
                            raising=False)
        panel._paste()
        assert d.alert_titles == ["Wrong length"]
        assert f"has {count}" in d.alerts[0][1]
        assert panel.has_input() is False

    def test_unknown_words_are_confirmed_before_filling(self, panel, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        d = _Dialogs(monkeypatch, dec, answer=False)
        text = " ".join(["zzz1", "zzz2"] + ["zoo"] * 48)
        monkeypatch.setattr(type(panel), "clipboard_get", lambda self: text,
                            raising=False)
        panel._paste()
        assert d.confirms and d.confirms[0][0] == "Unknown words"
        assert panel.has_input() is False, "declining must not touch the grid"

        d.answer = True
        panel._paste()
        assert panel.get_mnemonic().split()[0] == "zzz1"
        assert panel.valid_count() == 48        # the two junk words stay invalid


# ═════════════════════════════════════════════════════════════════════════════
# DecryptorApp — construction and file loading
# ═════════════════════════════════════════════════════════════════════════════


@requires_tkinter
class TestDecryptorConstruction:
    """What the window shows before anything is opened, and what changes once a
    payload is handed in at construction time."""

    def test_an_empty_window_prompts_for_a_file_and_disables_the_actions(self,
                                                                        app_factory):
        from quantacrypt.ui.decryptor import (FILE_PROMPT, SEC_HINT_EMPTY,
                                              OUT_HINT_EMPTY, FILE_SUB_NODROP)
        app = app_factory()
        texts = _widget_texts(app)
        assert FILE_PROMPT in texts
        assert SEC_HINT_EMPTY in texts
        assert app._out_hint.cget("text") == OUT_HINT_EMPTY
        assert app._btn._enabled is False and app._verify_btn._enabled is False
        assert app._sec_label.cget("text") == "2  PASSWORD"
        # tkinterdnd2 is absent here, so the card must not promise drag & drop
        assert app._file_card._line2.cget("text") == FILE_SUB_NODROP
        assert app.title() == "QuantaCrypt · Decrypt"

    def test_a_payload_with_a_path_loads_the_card_and_the_password_field(self,
                                                                        loaded_app):
        app, qcx = loaded_app
        assert app._btn._enabled is True and app._verify_btn._enabled is True
        assert hasattr(app, "_pw")
        assert app._out.get() == os.path.dirname(os.path.abspath(qcx))
        assert os.path.basename(qcx) in _widget_texts(app._file_card)

    def test_a_payload_without_a_path_still_builds_the_secret_section(self,
                                                                     app_factory,
                                                                     qcx_sample):
        _src, meta = qcx_sample
        app = app_factory(payload={"meta": meta})
        assert hasattr(app, "_pw")
        assert app._out.get() == ""            # nothing to suggest without a path
        assert app._btn._enabled is True

    def test_drag_and_drop_is_advertised_only_when_it_registers(self, ui_root,
                                                                tmp_path, monkeypatch):
        from quantacrypt.ui.decryptor import FILE_SUB_DROP, FILE_SUB_NODROP
        dec = _quiet(monkeypatch, tmp_path)
        monkeypatch.setattr(dec, "_DND_FILES", "DND_Files")
        monkeypatch.setattr(dec.DecryptorApp, "drop_target_register",
                            lambda self, *a: None, raising=False)
        monkeypatch.setattr(dec.DecryptorApp, "dnd_bind",
                            lambda self, *a: None, raising=False)
        app = _make_app(ui_root, dec)
        try:
            assert app._file_card._line2.cget("text") == FILE_SUB_DROP
        finally:
            app.destroy()

        def _refuse(self, *a):
            raise RuntimeError("tkdnd not loaded")

        monkeypatch.setattr(dec.DecryptorApp, "drop_target_register", _refuse,
                            raising=False)
        app2 = _make_app(ui_root, dec)
        try:
            assert app2._file_card._line2.cget("text") == FILE_SUB_NODROP
        finally:
            app2.destroy()

    def test_a_home_button_appears_only_with_a_launcher_behind_it(self, ui_root,
                                                                  tmp_path,
                                                                  monkeypatch):
        dec = _quiet(monkeypatch, tmp_path)
        with_home = _make_app(ui_root, dec, closed=lambda: None)
        try:
            assert any("Home" in t for t in _widget_texts(with_home))
        finally:
            with_home.destroy()

        standalone = dec.DecryptorApp(ui_root, on_close=None)
        standalone.geometry("620x780-4000-4000")
        standalone.update()
        try:
            assert not any("Home" in t for t in _widget_texts(standalone))
        finally:
            standalone.destroy()

    def test_center_at_places_the_window_around_the_given_point(self, app_factory):
        # Asserted on the requested geometry rather than winfo_x/y: the window
        # manager is free to nudge a real window, and this pins the arithmetic.
        app = app_factory()
        app.update_idletasks()
        w, h = app.winfo_width(), app.winfo_height()
        app._center(center_at=(700, 600))
        assert app.geometry().split("+")[1:] == [str(max(0, 700 - w // 2)),
                                                 str(max(0, 600 - h // 2))]

    def test_center_clamps_to_the_top_left_corner(self, app_factory):
        app = app_factory()
        app._center(center_at=(0, 0))
        assert app.geometry().split("+")[1:] == ["0", "0"]

    def test_center_without_a_point_uses_the_screen_middle(self, app_factory):
        app = app_factory()
        app.update_idletasks()
        w, h = app.winfo_width(), app.winfo_height()
        app._center()
        assert app.geometry().split("+")[1:] == [
            str(max(0, app.winfo_screenwidth() // 2 - w // 2)),
            str(max(0, app.winfo_screenheight() // 2 - h // 2))]


@requires_tkinter
class TestStatusLine:
    """Two lines under the action row: a neutral one and a red one, plus the
    "busy" flash the shortcuts use."""

    def test_status_is_grey_and_error_is_red(self, app_factory):
        app = app_factory()
        app._set_status("working", "detail here")
        assert app._err.cget("text") == "working"
        assert str(app._err.cget("fg")) == C["text3"]
        assert app._err_detail.cget("text") == "detail here"

        app._set_error("it broke", "technical")
        assert app._err.cget("text") == "it broke"
        assert str(app._err.cget("fg")) == C["error"]
        assert app._err_detail.cget("text") == "technical"

    def test_the_busy_flash_clears_itself(self, app_factory):
        app = app_factory()
        app._flash_busy()
        assert app._err.cget("text").startswith("Busy")
        assert _pump_until(app, lambda: app._err.cget("text") == "", timeout=5.0), \
            "the flash must clear itself after ~2s"

    def test_the_busy_flash_does_not_clobber_a_later_message(self, app_factory):
        app = app_factory()
        app._flash_busy()
        app._set_error("a real problem")
        _pump(app, 2.4)
        assert app._err.cget("text") == "a real problem"


@requires_tkinter
class TestFileOpening:
    """``_on_file`` turns every failure into one plain sentence; OS errors never
    leak a path or a traceback."""

    def test_opening_a_real_qcx_loads_it(self, app_factory, tmp_path, qcx_sample):
        import shutil
        src, _meta = qcx_sample
        qcx = tmp_path / "opened.qcx"
        shutil.copy(src, qcx)
        app = app_factory()
        app._on_file(str(qcx))
        assert app._meta["mode"] == "single"
        assert app._qcx_path == str(qcx)
        assert app._payload is not None
        assert app.title().startswith("opened.qcx —")
        assert app._err.cget("text") == ""
        assert app._out.get() == str(tmp_path)

    def test_a_shamir_qcx_switches_the_section_to_shares(self, app_factory,
                                                         shamir_sample):
        path, _meta, _shares = shamir_sample
        app = app_factory()
        app._on_file(path)
        assert app._mode_val == "shamir"
        assert app._sec_label.cget("text") == "2  SHARES"
        assert len(app._inputs) == 2                     # threshold slots
        assert "Enter any 2 of the 3 shares to unlock this file." in \
            _widget_texts(app._sec_wrap)

    def test_a_plain_file_is_not_a_quantacrypt_file(self, app_factory, tmp_path):
        junk = tmp_path / "notes.txt"
        junk.write_bytes(b"just some bytes")
        app = app_factory()
        app._on_file(str(junk))
        assert "isn't a QuantaCrypt .qcx file" in app._err.cget("text")
        assert app._payload is None

    def test_a_damaged_envelope_is_reported_as_damaged(self, app_factory, tmp_path):
        bad = tmp_path / "damaged.qcx"
        bad.write_bytes(MAGIC + struct.pack(">I", 9999) + b"{")
        app = app_factory()
        app._on_file(str(bad))
        assert app._err.cget("text") == "This .qcx file is damaged and can't be read."
        assert app._err_detail.cget("text")          # the technical second line
        assert app._payload is None

    def test_a_newer_format_asks_the_user_to_upgrade(self, app_factory, tmp_path):
        nf = tmp_path / "future.qcx"
        nf.write_bytes(make_pkg_bytes({"mode": "single", "version": 99}))
        app = app_factory()
        app._on_file(str(nf))
        assert "newer version" in app._err.cget("text")

    def test_an_older_format_says_so(self, app_factory, tmp_path):
        of = tmp_path / "ancient.qcx"
        of.write_bytes(make_pkg_bytes({"mode": "single", "version": 0}))
        app = app_factory()
        app._on_file(str(of))
        assert "older format" in app._err.cget("text")

    def test_a_missing_file_does_not_leak_the_path(self, app_factory, tmp_path):
        app = app_factory()
        ghost = str(tmp_path / "no such file.qcx")
        app._on_file(ghost)
        assert app._err.cget("text") == "Couldn't open that file."
        assert ghost not in app._err_detail.cget("text")
        assert app._payload is None

    def test_a_directory_is_rejected_without_crashing(self, app_factory, tmp_path):
        d = tmp_path / "a dir"
        d.mkdir()
        app = app_factory()
        app._on_file(str(d))
        assert app._err.cget("text") == "Couldn't open that file."

    def test_opening_a_second_file_resets_the_failure_counter(self, loaded_app,
                                                              tmp_path, qcx_sample):
        import shutil
        app, qcx = loaded_app
        app._pw_failures = 2
        other = tmp_path / "other.qcx"
        shutil.copy(qcx, other)
        app._on_file(str(other))
        assert app._pw_failures == 0
        assert app._qcx_path == str(other)


@requires_tkinter
class TestDrop:
    """A drop is one file: folders and empty drops are refused, a multi-file
    drop says which one it took."""

    def _event(self, data):
        import types
        return types.SimpleNamespace(data=data)

    def test_a_single_qcx_is_opened(self, loaded_app, tmp_path, qcx_sample):
        import shutil
        app, _qcx = loaded_app
        src, _meta = qcx_sample
        dropped = tmp_path / "dropped.qcx"
        shutil.copy(src, dropped)
        app._on_drop(self._event(str(dropped)))
        assert app._qcx_path == str(dropped)
        assert app._err.cget("text") == ""

    def test_a_folder_is_refused(self, loaded_app, tmp_path):
        app, qcx = loaded_app
        d = tmp_path / "folder"
        d.mkdir()
        app._on_drop(self._event(str(d)))
        assert "That's a folder" in app._err.cget("text")
        assert app._qcx_path == qcx

    def test_nothing_usable_is_refused(self, loaded_app, tmp_path):
        app, _qcx = loaded_app
        app._on_drop(self._event(str(tmp_path / "ghost.qcx")))
        assert "Nothing usable was dropped" in app._err.cget("text")

    def test_two_files_use_the_first(self, loaded_app, tmp_path, qcx_sample):
        import shutil
        app, _qcx = loaded_app
        src, _meta = qcx_sample
        a = tmp_path / "first.qcx"; shutil.copy(src, a)
        b = tmp_path / "second.qcx"; shutil.copy(src, b)
        app._on_drop(self._event(f"{a} {b}"))
        assert app._qcx_path == str(a)
        # BUG (documented, not fixed here): _on_drop sets the "Only one file
        # can be decrypted at a time — using first.qcx." notice and then calls
        # _on_file, whose first statement is _set_status(""), so the notice is
        # wiped before it can be read.  Asserting the real behaviour.
        assert app._err.cget("text") == ""

    def test_a_path_with_spaces_survives_the_tcl_split(self, loaded_app, tmp_path,
                                                       qcx_sample):
        import shutil
        app, _qcx = loaded_app
        src, _meta = qcx_sample
        d = tmp_path / "my folder"; d.mkdir()
        p = d / "with space.qcx"; shutil.copy(src, p)
        app._on_drop(self._event("{" + str(p) + "}"))
        assert app._qcx_path == str(p)

    def test_a_drop_while_busy_only_flashes(self, loaded_app, tmp_path):
        app, qcx = loaded_app
        app._busy = True
        try:
            app._on_drop(self._event(str(tmp_path / "whatever.qcx")))
            assert app._err.cget("text").startswith("Busy")
            assert app._qcx_path == qcx
        finally:
            app._busy = False

    def test_a_name_tcl_cannot_parse_falls_back_to_brace_splitting(self, loaded_app,
                                                                   tmp_path,
                                                                   qcx_sample):
        """A '{' in the filename makes TkDnD's payload an unbalanced Tcl list,
        so ``splitlist`` raises and the hand-rolled brace split has to cope."""
        import shutil
        app, _qcx = loaded_app
        src, _meta = qcx_sample
        p = tmp_path / "we{ird.qcx"
        shutil.copy(src, p)
        payload = "{" + str(p) + "}"
        with pytest.raises(Exception):
            app.tk.splitlist(payload)      # precondition for this test
        app._on_drop(self._event(payload))
        assert app._qcx_path == str(p)
        assert app._err.cget("text") == ""


@requires_tkinter
class TestInspectPopup:
    """"View file details" answers what can be known without any credential."""

    def test_the_popup_lists_the_public_metadata(self, loaded_app):
        app, qcx = loaded_app
        app._show_inspect()
        win = app.winfo_children()[-1]
        try:
            texts = _widget_texts(win)
            assert os.path.basename(qcx) in texts
            assert "A password, slowed down against guessing (Argon2id)" in texts
            assert any("QuantaCrypt file format v" in t for t in texts)
            assert any("(first 64 KB, SHA-256)" in t for t in texts)
            assert any(t.startswith("File size") or "KB" in t for t in texts)
        finally:
            win.destroy()

    def test_the_shamir_popup_names_the_scheme(self, shamir_app):
        app, _meta, _shares = shamir_app
        app._show_inspect()
        win = app.winfo_children()[-1]
        try:
            assert "A split key. Any 2 of 3 shares unlock it (Shamir secret sharing)" \
                in _widget_texts(win)
        finally:
            win.destroy()

    def test_a_vanished_file_still_renders_the_popup(self, loaded_app):
        app, qcx = loaded_app
        os.remove(qcx)
        app._show_inspect()
        win = app.winfo_children()[-1]
        try:
            texts = _widget_texts(win)
            assert "unknown" in texts                      # size unavailable
            assert not any("SHA-256" in t for t in texts)  # no fingerprint either
        finally:
            win.destroy()

    def test_escape_closes_the_popup(self, loaded_app):
        app, _qcx = loaded_app
        app._show_inspect()
        win = app.winfo_children()[-1]
        _press(win, "<Escape>")
        assert not win.winfo_exists()

    def test_nothing_opens_without_a_loaded_file(self, app_factory):
        app = app_factory()
        before = len(app.winfo_children())
        app._show_inspect()
        assert len(app.winfo_children()) == before

    def test_nothing_opens_when_the_path_is_unknown(self, app_factory, qcx_sample):
        _src, meta = qcx_sample
        app = app_factory(payload={"meta": meta})     # meta but no qcx_path
        before = len(app.winfo_children())
        app._show_inspect()
        assert len(app.winfo_children()) == before


@requires_tkinter
class TestPasswordReveal:
    """The Show/Hide toggle beside the password field."""

    def test_toggling_reveals_then_re_masks(self, loaded_app):
        app, _qcx = loaded_app
        assert str(app._pw.cget("show")) == "•"
        app._toggle_pw()
        assert str(app._pw.cget("show")) == ""
        assert app._eye_btn.cget("text") == "Hide"
        app._toggle_pw()
        assert str(app._pw.cget("show")) == "•"
        assert app._eye_btn.cget("text") == "Show"

    def test_the_toggle_is_inert_without_a_password_field(self, shamir_app):
        app, _meta, _shares = shamir_app
        assert not hasattr(app, "_pw")
        assert app._toggle_pw() is None
        assert not hasattr(app, "_pw") and not hasattr(app, "_eye_btn"), \
            "a share file must not grow a password field by being toggled"


# ═════════════════════════════════════════════════════════════════════════════
# Share entry
# ═════════════════════════════════════════════════════════════════════════════


@requires_tkinter
class TestShareSlots:
    """Slot management for a 2-of-3 file: k slots up front, spares up to the
    file's total, and a counter that always agrees with the inputs."""

    def test_a_shamir_file_opens_with_threshold_slots(self, shamir_app):
        app, _meta, _shares = shamir_app
        assert len(app._inputs) == 2
        assert app._slot_count() == 2
        assert app._share_counter.cget("text") == "0 of 2 shares complete"
        assert app._inputs[0]._expanded is True
        assert app._inputs[1]._expanded is False, "only the first panel starts open"

    def test_adding_a_spare_stops_at_the_files_total(self, shamir_app):
        app, _meta, _shares = shamir_app
        app._add_share_slot()
        assert app._slot_count() == 3
        assert app._add_btn._enabled is False
        assert app._add_hint.cget("text") == "This file was split into 3 shares."
        app._add_share_slot()
        assert app._slot_count() == 3, "the 4th slot must be refused"

    def test_the_add_button_opens_and_focuses_the_new_panel(self, shamir_app):
        """A spare added by hand is where the user is about to type, so it is
        expanded and focused — unlike the ones filled in bulk."""
        app, _meta, _shares = shamir_app
        app._add_btn._fire()
        app.update()
        assert app._slot_count() == 3
        assert app._inputs[2]._expanded is True
        assert app.focus_lastfor() is app._inputs[2]._cells[0]._e

    def test_the_add_button_focuses_a_new_code_field_too(self, shamir_app):
        app, _meta, _shares = shamir_app
        app._imode.set("raw"); app.update()
        app._add_btn._fire()
        app.update()
        assert len(app._entries) == 3
        assert app.focus_lastfor() is app._entries[2]

    def test_the_counter_counts_complete_panels_only(self, shamir_app):
        app, _meta, shares = shamir_app
        app._inputs[0].set_words(_mnemonic_for(shares[0]).split()[:49])
        app._update_share_counter()
        assert app._share_counter.cget("text") == "0 of 2 shares complete"

        app._inputs[0].set_words(_mnemonic_for(shares[0]).split())
        app._update_share_counter()
        assert app._share_counter.cget("text") == "1 of 2 shares complete"
        assert str(app._share_counter.cget("fg")) == C["warning"]

        app._inputs[1].set_words(_mnemonic_for(shares[1]).split())
        app._update_share_counter()
        assert app._share_counter.cget("text") == \
            f"2 of 2 shares complete  {ICON['ok']}"
        assert str(app._share_counter.cget("fg")) == C["success"]

    def test_the_counter_never_exceeds_the_threshold(self, shamir_app):
        app, _meta, shares = shamir_app
        app._add_share_slot()
        for i in range(3):
            app._inputs[i].set_words(_mnemonic_for(shares[i]).split())
        app._update_share_counter()
        assert app._share_counter.cget("text") == \
            f"2 of 2 shares complete  {ICON['ok']}"

    def test_the_counter_is_silent_before_the_section_exists(self, app_factory):
        """A password file never builds the counter, but the panels' change
        hooks can still fire at it — it must return without inventing one."""
        app = app_factory()
        assert not hasattr(app, "_share_counter")
        assert app._update_share_counter() is None
        assert not hasattr(app, "_share_counter")

    def test_the_counter_survives_its_own_widget_being_destroyed(self, shamir_app):
        import tkinter as tk
        app, _meta, shares = shamir_app
        app._inputs[0].set_words(_mnemonic_for(shares[0]).split())
        app._update_share_counter()
        assert app._share_counter.cget("text") == "1 of 2 shares complete"

        app._share_counter.destroy()
        with pytest.raises(tk.TclError):
            app._share_counter.config(text="x")   # the write it has to skip
        assert app._update_share_counter() is None

    def test_the_add_button_forgets_itself_when_the_row_is_torn_down(self,
                                                                    shamir_app):
        app, _meta, _shares = shamir_app
        app._add_hint.destroy()
        app._refresh_add_btn()
        assert app._add_btn is None
        app._refresh_add_btn()          # second call must be a no-op

    def test_share_done_moves_to_the_next_empty_panel(self, shamir_app):
        app, _meta, shares = shamir_app
        app._inputs[1].collapse()
        app._inputs[0].set_words(_mnemonic_for(shares[0]).split())
        app._share_done(0)
        assert app._inputs[1]._expanded is True, "the next panel is opened for input"

    def test_share_done_is_inert_while_busy(self, shamir_app):
        app, _meta, _shares = shamir_app
        app._inputs[1].collapse()
        app._busy = True
        try:
            app._share_done(0)
            assert app._inputs[1]._expanded is False
        finally:
            app._busy = False

    def test_share_done_submits_once_the_threshold_is_met(self, shamir_app):
        app, _meta, shares = shamir_app
        for i in range(2):
            app._inputs[i].set_words(_mnemonic_for(shares[i]).split())
        app._out.delete(0, "end")               # no output folder → validation error
        app._share_done(1)
        assert "Choose a folder" in app._err.cget("text"), \
            "the last share submits the form rather than hunting for another slot"


@requires_tkinter
class TestRawShareEntries:
    """The QCSHARE- code mode: per-field validity glyph, paste helpers, and the
    counter shared with the mnemonic mode."""

    @pytest.fixture
    def raw_app(self, shamir_app):
        app, meta, shares = shamir_app
        app._imode.set("raw")
        app.update()
        return app, meta, shares

    def test_switching_mode_builds_code_entries(self, raw_app):
        app, _meta, _shares = raw_app
        assert app._inputs == [] and len(app._entries) == 2
        assert len(app._entry_marks) == 2

    def test_a_valid_code_marks_the_field_green(self, raw_app):
        app, _meta, shares = raw_app
        app._entries[0].insert(0, shares[0])
        app._mark_entry(app._entries[0])
        assert app._entry_marks[0].cget("text") == ICON["ok"]
        assert str(app._entries[0].cget("highlightbackground")) == C["success"]

    def test_junk_marks_the_field_red(self, raw_app):
        app, _meta, _shares = raw_app
        app._entries[0].insert(0, "not-a-share")
        app._mark_entry(app._entries[0])
        assert app._entry_marks[0].cget("text") == ICON["err"]
        assert str(app._entries[0].cget("highlightbackground")) == C["error"]

    def test_an_empty_field_carries_no_glyph(self, raw_app):
        app, _meta, _shares = raw_app
        app._entries[0].insert(0, "x")
        app._mark_entry(app._entries[0])
        app._entries[0].delete(0, "end")
        app._mark_entry(app._entries[0])
        assert app._entry_marks[0].cget("text") == ""
        assert str(app._entries[0].cget("highlightbackground")) == C["border"]

    def test_marking_a_widget_that_is_not_a_share_field_moves_no_glyph(self,
                                                                        raw_app,
                                                                        ui_root):
        """``list.index`` raises for a stranger; the guard must not fall
        through and repaint slot 0's glyph with the stranger's contents."""
        import tkinter as tk
        app, _meta, shares = raw_app
        app._entries[0].insert(0, shares[0])
        app._mark_entry(app._entries[0])
        assert app._entry_marks[0].cget("text") == ICON["ok"]

        stray = tk.Entry(ui_root)
        stray.insert(0, "not-a-share")
        with pytest.raises(ValueError):
            app._entries.index(stray)          # what _mark_entry has to survive
        assert app._mark_entry(stray) is None
        assert app._entry_marks[0].cget("text") == ICON["ok"], "untouched"
        assert str(app._entries[0].cget("highlightbackground")) == C["success"]
        stray.destroy()

    def test_typing_updates_the_glyph_and_the_counter(self, raw_app):
        app, _meta, shares = raw_app
        app._entries[0].insert(0, shares[0])
        _press(app._entries[0], "<KeyRelease-a>")
        assert app._entry_marks[0].cget("text") == ICON["ok"]
        assert app._share_counter.cget("text") == "1 of 2 shares complete"

    def test_a_paste_event_is_validated_after_the_text_lands(self, raw_app):
        app, _meta, shares = raw_app
        app._entries[1].insert(0, shares[1])
        app._entries[1].event_generate("<<Paste>>")
        assert _pump_until(app, lambda: app._entry_marks[1].cget("text") == ICON["ok"],
                           timeout=2.0)

    def test_return_in_the_last_field_submits(self, raw_app):
        app, _meta, shares = raw_app
        for e, s in zip(app._entries, shares):
            e.insert(0, s)
        app._out.delete(0, "end")
        _press(app._entries[1], "<Return>")
        assert "Choose a folder" in app._err.cget("text")

    def test_return_in_a_field_moves_to_the_next_empty_one(self, raw_app):
        app, _meta, shares = raw_app
        app._entries[0].insert(0, shares[0])
        app._share_done(0)
        app.update()
        assert app.focus_lastfor() is app._entries[1]

    def test_paste_into_one_field_takes_the_qcshare_line(self, raw_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = raw_app
        _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(type(app), "clipboard_get",
                            lambda self: f"Share 1 of 3\n{shares[0]}\nkeep safe",
                            raising=False)
        app._paste_single_share(app._entries[0])
        assert app._entries[0].get() == shares[0]
        assert app._entry_marks[0].cget("text") == ICON["ok"]
        assert app._share_counter.cget("text") == "1 of 2 shares complete"

    def test_the_row_paste_button_fills_its_own_field(self, raw_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = raw_app
        _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(type(app), "clipboard_get", lambda self: shares[1],
                            raising=False)
        from quantacrypt.ui.shared import FlatButton
        row = app._entries[1].master
        row_paste = [w for w in row.winfo_children() if isinstance(w, FlatButton)][0]
        row_paste._fire()
        assert app._entries[1].get() == shares[1]
        assert app._entries[0].get() == "", "only its own row is filled"

    def test_paste_into_one_field_uses_the_whole_text_when_there_is_no_code(self,
                                                                           raw_app,
                                                                           monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, _shares = raw_app
        _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(type(app), "clipboard_get", lambda self: "  nonsense  ",
                            raising=False)
        app._paste_single_share(app._entries[0])
        assert app._entries[0].get() == "nonsense"
        assert app._entry_marks[0].cget("text") == ICON["err"]

    def test_paste_into_one_field_with_an_empty_clipboard(self, raw_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, _shares = raw_app
        d = _Dialogs(monkeypatch, dec)

        def _boom(self):
            raise Exception("empty")

        monkeypatch.setattr(type(app), "clipboard_get", _boom, raising=False)
        app._paste_single_share(app._entries[0])
        assert d.alert_titles == ["Nothing to paste"]
        assert app._entries[0].get() == ""


@requires_tkinter
class TestBulkShareLoading:
    """"Paste all" and "Load from file…" share one code path, so both fill the
    slots in order and both report what they could not read."""

    def test_paste_all_fills_every_slot(self, shamir_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = shamir_app
        _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(type(app), "clipboard_get",
                            lambda self: f"{shares[0]}\n{shares[1]}\n", raising=False)
        app._paste_all_shares()
        assert app._inputs[0].is_complete() and app._inputs[1].is_complete()
        assert app._share_counter.cget("text").startswith("2 of 2")
        assert "Loaded 2 shares from the clipboard." == app._err.cget("text")

    def test_paste_all_collapses_every_panel_but_the_first(self, shamir_app,
                                                           monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = shamir_app
        _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(type(app), "clipboard_get",
                            lambda self: f"{shares[0]}\n{shares[1]}\n", raising=False)
        app._paste_all_shares()
        assert app._inputs[0]._expanded is True
        assert app._inputs[1]._expanded is False

    def test_paste_all_with_an_empty_clipboard(self, shamir_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, _shares = shamir_app
        d = _Dialogs(monkeypatch, dec)

        def _boom(self):
            raise Exception("empty")

        monkeypatch.setattr(type(app), "clipboard_get", _boom, raising=False)
        app._paste_all_shares()
        assert d.alert_titles == ["Nothing to paste"]

    def test_a_clipboard_with_no_shares_says_so(self, shamir_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, _shares = shamir_app
        d = _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(type(app), "clipboard_get", lambda self: "hello",
                            raising=False)
        app._paste_all_shares()
        assert d.alert_titles == ["No shares found"]
        assert "the clipboard" in d.alerts[0][1]

    def test_too_few_shares_is_confirmed_first(self, shamir_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = shamir_app
        d = _Dialogs(monkeypatch, dec, answer=False)
        monkeypatch.setattr(type(app), "clipboard_get", lambda self: shares[0],
                            raising=False)
        app._paste_all_shares()
        assert d.confirms and d.confirms[0][0] == "Not enough shares"
        assert app._inputs[0].has_input() is False, "declining fills nothing"

        d.answer = True
        app._paste_all_shares()
        assert app._inputs[0].is_complete() is True
        assert "Loaded 1 share from the clipboard." == app._err.cget("text")

    def test_more_codes_than_slots_grows_the_form(self, shamir_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = shamir_app
        _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(type(app), "clipboard_get", lambda self: "\n".join(shares),
                            raising=False)
        app._paste_all_shares()
        assert app._slot_count() == 3
        assert all(i.is_complete() for i in app._inputs)

    def test_an_unreadable_code_names_the_slot_it_could_not_fill(self, shamir_app,
                                                                 monkeypatch):
        app, _meta, shares = shamir_app
        # A share whose modulus is wrong decodes but cannot become a mnemonic.
        broken = cc.encode_share({"index": 1, "value": -1, "modulus": 7})
        app._fill_shares([shares[0], broken])
        assert app._inputs[0].is_complete() is True
        assert app._inputs[1].has_input() is False
        assert "Share 2 couldn't be read" in app._err.cget("text")

    def test_fill_shares_clears_slots_it_has_no_code_for(self, shamir_app):
        app, _meta, shares = shamir_app
        app._inputs[1].set_words(_mnemonic_for(shares[1]).split())
        app._fill_shares([shares[0]])
        assert app._inputs[0].is_complete() is True
        assert app._inputs[1].has_input() is False

    def test_fill_shares_in_raw_mode_writes_the_codes_verbatim(self, shamir_app):
        app, _meta, shares = shamir_app
        app._imode.set("raw")
        app.update()
        app._entries[1].insert(0, "stale")
        app._fill_shares([shares[0]])
        assert app._entries[0].get() == shares[0]
        assert app._entries[1].get() == ""
        assert app._entry_marks[0].cget("text") == ICON["ok"]

    # ── Load from file ───────────────────────────────────────────────────────

    def _pick(self, monkeypatch, dec, paths):
        monkeypatch.setattr(dec.filedialog, "askopenfilenames",
                            lambda **kw: tuple(paths))

    def test_loading_two_share_files_fills_both_slots(self, shamir_app, tmp_path,
                                                      monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = shamir_app
        _Dialogs(monkeypatch, dec)
        files = []
        for i, s in enumerate(shares[:2], 1):
            p = tmp_path / f"secret.share-{i}-of-3.txt"
            p.write_text(f"QuantaCrypt share {i} of 3\n\n{s}\n")
            files.append(str(p))
        self._pick(monkeypatch, dec, files)
        app._load_shares_from_files()
        assert app._inputs[0].is_complete() and app._inputs[1].is_complete()
        assert "from those files" in app._err.cget("text")

    def test_a_single_file_is_described_in_the_singular(self, shamir_app, tmp_path,
                                                        monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = shamir_app
        _Dialogs(monkeypatch, dec)
        p = tmp_path / "both.txt"
        p.write_text("\n".join(shares[:2]))
        self._pick(monkeypatch, dec, [str(p)])
        app._load_shares_from_files()
        assert "from that file" in app._err.cget("text")

    def test_duplicate_codes_across_files_are_collapsed(self, shamir_app, tmp_path,
                                                        monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = shamir_app
        d = _Dialogs(monkeypatch, dec, answer=True)
        a = tmp_path / "a.txt"; a.write_text(shares[0])
        b = tmp_path / "b.txt"; b.write_text(shares[0])
        self._pick(monkeypatch, dec, [str(a), str(b)])
        app._load_shares_from_files()
        assert d.confirms[0][0] == "Not enough shares"
        assert app._inputs[1].has_input() is False

    def test_cancelling_the_dialog_changes_nothing(self, shamir_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, _shares = shamir_app
        self._pick(monkeypatch, dec, [])
        app._load_shares_from_files()
        assert app._err.cget("text") == ""
        assert app._inputs[0].has_input() is False

    def test_a_file_past_the_size_cap_is_refused_even_though_it_holds_a_code(
            self, shamir_app, tmp_path, monkeypatch):
        """n+1 bytes.  The file carries a perfectly good share, so only the cap
        can be what stops it — a "no codes in it" pass would look identical."""
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = shamir_app
        d = _Dialogs(monkeypatch, dec)
        big = tmp_path / "huge.txt"
        big.write_text(shares[0] + "\n" + "x" * (dec._MAX_SHARE_FILE + 1))
        assert big.stat().st_size > dec._MAX_SHARE_FILE
        self._pick(monkeypatch, dec, [str(big)])
        app._load_shares_from_files()
        assert app._err.cget("text") == "Couldn't read huge.txt."
        assert d.alert_titles == ["No shares found"]
        assert app._inputs[0].has_input() is False, "nothing was read out of it"

    def test_a_file_exactly_on_the_size_cap_is_still_read(self, shamir_app,
                                                          tmp_path, monkeypatch):
        """n.  The guard is ``>``, so the boundary file itself is fine."""
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = shamir_app
        _Dialogs(monkeypatch, dec, answer=True)
        body = (shares[0] + "\n").encode()
        at_cap = tmp_path / "at-cap.txt"
        at_cap.write_bytes(body + b"x" * (dec._MAX_SHARE_FILE - len(body)))
        assert at_cap.stat().st_size == dec._MAX_SHARE_FILE
        self._pick(monkeypatch, dec, [str(at_cap)])
        app._load_shares_from_files()
        assert app._inputs[0].is_complete() is True
        assert "Couldn't read" not in app._err.cget("text")

    def test_one_oversized_file_does_not_stop_the_readable_one(self, shamir_app,
                                                               tmp_path,
                                                               monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = shamir_app
        _Dialogs(monkeypatch, dec)
        big = tmp_path / "huge.txt"
        big.write_bytes(b"x" * (dec._MAX_SHARE_FILE + 1))
        ok = tmp_path / "ok.txt"; ok.write_text("\n".join(shares[:2]))
        self._pick(monkeypatch, dec, [str(big), str(ok)])
        app._load_shares_from_files()
        # The status line ends up on the success message, but the failure was
        # reported first and the readable file still filled the slots.
        assert app._inputs[0].is_complete() and app._inputs[1].is_complete()
        assert app._err.cget("text") == "Loaded 2 shares from those files."

    def test_an_unreadable_file_is_reported(self, shamir_app, tmp_path, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, _shares = shamir_app
        _Dialogs(monkeypatch, dec)
        self._pick(monkeypatch, dec, [str(tmp_path / "gone.txt")])
        app._load_shares_from_files()
        assert "Couldn't read gone.txt." in _widget_texts(app)

    def test_loading_is_refused_while_busy(self, shamir_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, _shares = shamir_app
        called = []
        monkeypatch.setattr(dec.filedialog, "askopenfilenames",
                            lambda **kw: called.append(1) or ())
        app._busy = True
        try:
            app._load_shares_from_files()
            assert called == []
        finally:
            app._busy = False


@requires_tkinter
class TestShareFormatSwitch:
    """Switching between 50-word phrases and QCSHARE- codes throws away what
    was typed, so it is confirmed whenever there is anything to lose."""

    def test_switching_an_empty_form_needs_no_confirmation(self, shamir_app,
                                                           monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, _shares = shamir_app
        d = _Dialogs(monkeypatch, dec)
        app._imode.set("raw")
        app.update()
        assert d.confirms == []
        assert len(app._entries) == 2 and app._inputs == []

    def test_switching_with_data_and_declining_restores_the_mode(self, shamir_app,
                                                                 monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = shamir_app
        d = _Dialogs(monkeypatch, dec, answer=False)
        app._inputs[0].set_words(_mnemonic_for(shares[0]).split())
        app._imode.set("raw")
        app.update()
        assert d.confirms[0][0] == "Switch share format?"
        assert app._imode.get() == "mnemonic"
        assert app._inputs[0].is_complete() is True, "the typed share survives"

    def test_switching_with_data_and_accepting_clears_the_form(self, shamir_app,
                                                               monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = shamir_app
        _Dialogs(monkeypatch, dec, answer=True)
        app._inputs[0].set_words(_mnemonic_for(shares[0]).split())
        app._imode.set("raw")
        app.update()
        assert app._imode.get() == "raw"
        assert app._inputs == [] and len(app._entries) == 2
        assert all(e.get() == "" for e in app._entries)

    def test_raw_data_also_triggers_the_confirmation(self, shamir_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = shamir_app
        _Dialogs(monkeypatch, dec, answer=True)
        app._imode.set("raw")
        app.update()
        app._entries[0].insert(0, shares[0])
        d2 = _Dialogs(monkeypatch, dec, answer=False)
        app._imode.set("mnemonic")
        app.update()
        assert d2.confirms[0][0] == "Switch share format?"
        assert app._imode.get() == "raw"

    def test_a_password_file_ignores_the_share_mode_variable(self, loaded_app):
        app, _qcx = loaded_app
        app._imode.set("raw")
        app.update()
        assert hasattr(app, "_pw"), "the password form must survive"

    def test_a_stale_mode_trace_id_does_not_block_a_reload(self, shamir_app):
        """The id outlives the handler Tk registered it for, so a reload can
        find it already gone.  Detaching has to fail quietly AND the reload
        has to go on to install a working handler."""
        app, _meta, _shares = shamir_app
        app._imode_trace_id = "stale_no_such_command"
        app._load_payload()
        assert app._imode_trace_id not in (None, "stale_no_such_command")
        assert app._imode_trace_id in {name for _, name in app._imode.trace_info()}
        app._imode.set("raw")              # the fresh handler really is live
        app.update()
        assert app._inputs == [] and len(app._entries) == 2

    def test_reloading_a_shamir_file_replaces_its_own_mode_trace(self, shamir_app):
        """Re-rendering must not leave the previous render's handler attached:
        it would fire against the destroyed inputs frame."""
        app, _meta, _shares = shamir_app
        first = app._imode_trace_id
        app._load_payload()
        names = {name for _, name in app._imode.trace_info()}
        assert first not in names, "the previous handler is detached"
        assert app._imode_trace_id != first and app._imode_trace_id in names
        # NOTE: shared.SegmentedControl also traces this variable and never
        # detaches on destroy, so the total count does grow — that leak is in
        # shared.py, not here, and is reported separately.


@requires_tkinter
class TestBrowseOutput:
    """The "Choose…" button seeds the folder dialog from whatever is typed."""

    def test_choosing_a_folder_replaces_the_field(self, loaded_app, tmp_path,
                                                  monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        target = tmp_path / "chosen"
        target.mkdir()
        seen = {}
        monkeypatch.setattr(dec.filedialog, "askdirectory",
                            lambda **kw: seen.update(kw) or str(target))
        app._browse_out()
        assert app._out.get() == str(target)
        assert seen["initialdir"] == str(tmp_path)      # the current folder

    def test_a_typed_file_path_seeds_its_parent_folder(self, loaded_app, tmp_path,
                                                       monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        app._out.delete(0, "end")
        app._out.insert(0, str(tmp_path / "no-such-dir" / "file.bin"))
        seen = {}
        monkeypatch.setattr(dec.filedialog, "askdirectory",
                            lambda **kw: seen.update(kw) or "")
        app._browse_out()
        assert seen["initialdir"] == str(tmp_path / "no-such-dir")

    def test_an_empty_field_seeds_the_home_folder(self, loaded_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        app._out.delete(0, "end")
        seen = {}
        monkeypatch.setattr(dec.filedialog, "askdirectory",
                            lambda **kw: seen.update(kw) or "")
        app._browse_out()
        assert seen["initialdir"] == os.path.expanduser("~")

    def test_cancelling_leaves_the_field_alone(self, loaded_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        before = app._out.get()
        monkeypatch.setattr(dec.filedialog, "askdirectory", lambda **kw: "")
        app._browse_out()
        assert app._out.get() == before


# ═════════════════════════════════════════════════════════════════════════════
# Validation
# ═════════════════════════════════════════════════════════════════════════════


@requires_tkinter
class TestValidate:
    """``_validate`` returns the one sentence shown on the status line, or None
    when the form is ready."""

    def test_a_ready_password_form_validates(self, loaded_app, tmp_path):
        app, _qcx = loaded_app
        app._pw.insert(0, PW)
        assert app._validate() is None

    def test_no_file_open(self, app_factory, tmp_path):
        app = app_factory()
        app._out.insert(0, str(tmp_path))
        assert app._validate() == "Open a .qcx file first"

    def test_no_output_folder(self, loaded_app):
        app, _qcx = loaded_app
        app._out.delete(0, "end")
        app._pw.insert(0, PW)
        assert app._validate() == "Choose a folder to save the decrypted file in"

    def test_a_whitespace_only_output_folder_counts_as_empty(self, loaded_app):
        app, _qcx = loaded_app
        app._out.delete(0, "end"); app._out.insert(0, "   ")
        app._pw.insert(0, PW)
        assert app._validate() == "Choose a folder to save the decrypted file in"

    def test_an_output_folder_that_does_not_exist(self, loaded_app, tmp_path):
        app, _qcx = loaded_app
        app._out.delete(0, "end")
        app._out.insert(0, str(tmp_path / "nowhere"))
        app._pw.insert(0, PW)
        assert app._validate() == "That output folder doesn't exist. Choose another"

    def test_an_empty_password(self, loaded_app):
        app, _qcx = loaded_app
        assert app._validate() == "Enter your password"

    def test_a_single_character_password_is_accepted_for_decryption(self, loaded_app):
        # The 8-character floor guards encryption only; refusing a short
        # password here would lock users out of files that predate it.
        app, _qcx = loaded_app
        app._pw.insert(0, "x")
        assert app._validate() is None

    def test_a_very_long_unicode_password_is_accepted(self, loaded_app):
        app, _qcx = loaded_app
        app._pw.insert(0, "pässwörd-ünïcødé-Ω" * 50)
        assert app._validate() is None

    def test_shamir_with_no_shares_names_the_empty_slots(self, shamir_app):
        app, _meta, _shares = shamir_app
        assert app._validate() == \
            "Shares 1 and 2 are empty; this file needs 2 shares"

    def test_shamir_with_one_share_names_the_remaining_slot(self, shamir_app):
        app, _meta, shares = shamir_app
        app._inputs[0].set_words(_mnemonic_for(shares[0]).split())
        assert app._validate() == "Share 2 is empty; this file needs 2 shares"

    def test_a_half_typed_phrase_is_reported_with_its_progress(self, shamir_app):
        app, _meta, shares = shamir_app
        app._inputs[0].set_words(_mnemonic_for(shares[0]).split()[:30])
        assert app._validate() == "Incomplete: Share 1: 30/50 words"

    def test_two_half_typed_phrases_are_both_listed(self, shamir_app):
        app, _meta, shares = shamir_app
        app._inputs[0].set_words(_mnemonic_for(shares[0]).split()[:10])
        app._inputs[1].set_words(_mnemonic_for(shares[1]).split()[:20])
        assert app._validate() == \
            "Incomplete: Share 1: 10/50 words, Share 2: 20/50 words"

    def test_two_complete_phrases_validate(self, shamir_app):
        app, _meta, shares = shamir_app
        for i in range(2):
            app._inputs[i].set_words(_mnemonic_for(shares[i]).split())
        assert app._validate() is None

    def test_an_empty_spare_slot_is_ignored(self, shamir_app):
        app, _meta, shares = shamir_app
        app._add_share_slot()
        for i in range(2):
            app._inputs[i].set_words(_mnemonic_for(shares[i]).split())
        assert app._validate() is None

    def test_raw_mode_rejects_a_field_that_is_not_a_code(self, shamir_app):
        app, _meta, shares = shamir_app
        app._imode.set("raw"); app.update()
        app._entries[0].insert(0, "hello")
        app._entries[1].insert(0, shares[1])
        assert app._validate() == \
            "Share 1 doesn't look right: code shares start with QCSHARE-"

    def test_raw_mode_pluralises_two_bad_fields(self, shamir_app):
        app, _meta, _shares = shamir_app
        app._imode.set("raw"); app.update()
        app._entries[0].insert(0, "a")
        app._entries[1].insert(0, "b")
        assert app._validate() == \
            "Shares 1 and 2 don't look right: code shares start with QCSHARE-"

    def test_raw_mode_names_the_empty_field(self, shamir_app):
        app, _meta, shares = shamir_app
        app._imode.set("raw"); app.update()
        app._entries[0].insert(0, shares[0])
        assert app._validate() == "Share 2 is empty; this file needs 2 shares"

    def test_raw_mode_validates_when_both_codes_are_present(self, shamir_app):
        app, _meta, shares = shamir_app
        app._imode.set("raw"); app.update()
        for e, s in zip(app._entries, shares):
            e.insert(0, s)
        assert app._validate() is None


@requires_tkinter
class TestFocusHelpers:
    """After a validation error or a failed attempt, the cursor lands on the
    thing the message is about — expanding a collapsed panel if needed."""

    def test_a_password_error_focuses_the_password(self, loaded_app):
        app, _qcx = loaded_app
        app._focus_first_bad()
        app.update()
        assert app.focus_lastfor() is app._pw

    def test_a_bad_output_folder_focuses_the_folder_field(self, shamir_app, tmp_path):
        app, _meta, _shares = shamir_app
        app._out.delete(0, "end")
        app._focus_first_bad()
        app.update()
        assert app.focus_lastfor() is app._out

    def test_an_incomplete_phrase_is_expanded_and_focused(self, shamir_app,
                                                          shamir_sample):
        app, _meta, shares = shamir_app
        app._inputs[1].set_words(_mnemonic_for(shares[1]).split()[:5])
        app._inputs[1].collapse()
        app._focus_first_bad()
        assert app._inputs[1]._expanded is True

    def test_an_empty_phrase_slot_is_focused_when_nothing_is_partial(self,
                                                                    shamir_app):
        app, _meta, shares = shamir_app
        app._inputs[0].set_words(_mnemonic_for(shares[0]).split())
        app._inputs[1].collapse()
        app._focus_first_bad()
        assert app._inputs[1]._expanded is True

    def test_a_malformed_code_is_focused(self, shamir_app):
        app, _meta, shares = shamir_app
        app._imode.set("raw"); app.update()
        app._entries[0].insert(0, shares[0])
        app._entries[1].insert(0, "junk")
        app._focus_first_bad()
        app.update()
        assert app.focus_lastfor() is app._entries[1]

    def test_an_empty_code_field_is_focused(self, shamir_app, shamir_sample):
        app, _meta, shares = shamir_app
        app._imode.set("raw"); app.update()
        app._entries[0].insert(0, shares[0])
        app._focus_first_bad()
        app.update()
        assert app.focus_lastfor() is app._entries[1]

    def test_focus_survives_a_torn_down_form(self, loaded_app):
        """Both run from ``after`` hops that can outlive the form.  Swallowing
        is the contract, and the swallow is load-bearing: the focus call they
        make raises once the field is gone."""
        import tkinter as tk
        app, _qcx = loaded_app
        app._pw.destroy()
        with pytest.raises(tk.TclError):
            app._pw.focus_set()                    # what both have to survive
        assert app._focus_first_bad() is None
        assert app._focus_credential() is None

    def test_credential_focus_selects_the_password_for_retyping(self, loaded_app):
        app, _qcx = loaded_app
        app._pw.insert(0, "wrong")
        app._focus_credential()
        app.update()
        assert app.focus_lastfor() is app._pw
        assert app._pw.selection_present()

    def test_credential_focus_opens_the_first_share_panel(self, shamir_app):
        app, _meta, _shares = shamir_app
        app._inputs[0].collapse()
        app._focus_credential()
        assert app._inputs[0]._expanded is True

    def test_credential_focus_selects_the_first_code_field(self, shamir_app):
        app, _meta, shares = shamir_app
        app._imode.set("raw"); app.update()
        app._entries[0].insert(0, shares[0])
        app._focus_credential()
        app.update()
        assert app._entries[0].selection_present()

    def test_the_shares_wrong_copy_names_the_scheme(self, shamir_app):
        app, _meta, _shares = shamir_app
        copy = app._shares_wrong_copy()
        assert "Any 2 of the 3 shares will work" in copy

    def test_the_shares_wrong_copy_degrades_without_metadata(self, app_factory):
        app = app_factory()
        assert "Any ? of the ? shares" in app._shares_wrong_copy()


# ═════════════════════════════════════════════════════════════════════════════
# Collecting shares for the worker
# ═════════════════════════════════════════════════════════════════════════════


@requires_tkinter
class TestCollectShares:
    """Runs on the main thread before the worker starts, because Tk widget
    reads are not thread-safe.  It also rejects the two mistakes that would
    otherwise surface as a cryptic wrong-key error."""

    def test_the_first_k_complete_panels_become_codes(self, shamir_app):
        app, _meta, shares = shamir_app
        app._add_share_slot()
        for i in range(3):
            app._inputs[i].set_words(_mnemonic_for(shares[i]).split())
        collected = app._collect_shares()
        assert len(collected) == 2
        assert [cc.decode_share(c)["index"] for c in collected] == \
            [cc.decode_share(s)["index"] for s in shares[:2]]

    def test_incomplete_panels_are_skipped(self, shamir_app):
        app, _meta, shares = shamir_app
        app._inputs[0].set_words(_mnemonic_for(shares[0]).split()[:10])
        app._inputs[1].set_words(_mnemonic_for(shares[1]).split())
        collected = app._collect_shares()
        assert [cc.decode_share(c)["index"] for c in collected] == \
            [cc.decode_share(shares[1])["index"]]

    def test_the_same_share_twice_is_refused(self, shamir_app):
        app, _meta, shares = shamir_app
        for i in range(2):
            app._inputs[i].set_words(_mnemonic_for(shares[0]).split())
        with pytest.raises(ValueError, match="are the same share"):
            app._collect_shares()

    def test_a_share_for_a_different_encryption_is_named(self, shamir_app):
        app, _meta, shares = shamir_app
        app._inputs[0].set_words(_mnemonic_for(shares[0], threshold=4).split())
        with pytest.raises(ValueError, match="needs 4 people"):
            app._collect_shares()

    def test_raw_mode_returns_the_codes_as_typed(self, shamir_app):
        app, _meta, shares = shamir_app
        app._imode.set("raw"); app.update()
        for e, s in zip(app._entries, shares):
            e.insert(0, s)
        assert app._collect_shares() == shares[:2]

    def test_raw_mode_names_an_unreadable_code(self, shamir_app):
        app, _meta, shares = shamir_app
        app._imode.set("raw"); app.update()
        app._entries[0].insert(0, shares[0])
        app._entries[1].insert(0, "QCSHARE-not-base64!!")
        with pytest.raises(ValueError, match="Share 2 can't be read"):
            app._collect_shares()

    def test_raw_mode_rejects_a_duplicated_code(self, shamir_app):
        app, _meta, shares = shamir_app
        app._imode.set("raw"); app.update()
        for e in app._entries:
            e.insert(0, shares[0])
        with pytest.raises(ValueError, match="Shares 1 and 2 are the same share"):
            app._collect_shares()

    def test_empty_raw_fields_are_skipped(self, shamir_app):
        app, _meta, shares = shamir_app
        app._imode.set("raw"); app.update()
        app._entries[1].insert(0, shares[1])
        assert app._collect_shares() == [shares[1]]


# ═════════════════════════════════════════════════════════════════════════════
# Freeze / thaw and the progress bar
# ═════════════════════════════════════════════════════════════════════════════


@requires_tkinter
class TestFreezeThaw:
    """While a worker runs, nothing on the form may be edited — including the
    share panels and their Paste / Clear / Load buttons."""

    def test_freeze_then_thaw_round_trips_the_password_form(self, loaded_app):
        app, _qcx = loaded_app
        app._freeze()
        assert app._btn._enabled is False and app._verify_btn._enabled is False
        assert app._browse_btn._enabled is False
        assert str(app._out.cget("state")) == "disabled"
        assert str(app._pw.cget("state")) == "disabled"
        assert app._eye_btn._enabled is False

        app._thaw()
        assert app._btn._enabled is True and app._verify_btn._enabled is True
        assert app._browse_btn._enabled is True
        assert str(app._out.cget("state")) == "normal"
        assert str(app._pw.cget("state")) == "normal"
        assert app._eye_btn._enabled is True

    def test_freeze_reaches_the_share_panels_and_their_buttons(self, shamir_app):
        app, _meta, _shares = shamir_app
        app._freeze()
        assert all(str(c._e.cget("state")) == "disabled"
                   for inp in app._inputs for c in inp._cells)
        assert all(b._enabled is False for b in app._share_btns)
        app._thaw()
        assert all(str(c._e.cget("state")) == "normal"
                   for inp in app._inputs for c in inp._cells)
        assert all(b._enabled is True for b in app._share_btns)

    def test_freeze_disables_the_raw_code_fields(self, shamir_app):
        app, _meta, _shares = shamir_app
        app._imode.set("raw"); app.update()
        app._freeze()
        assert all(str(e.cget("state")) == "disabled" for e in app._entries)
        app._thaw()
        assert all(str(e.cget("state")) == "normal" for e in app._entries)

    def test_thawing_without_a_payload_leaves_verify_disabled(self, app_factory):
        app = app_factory()
        app._thaw()
        assert app._verify_btn._enabled is False
        assert app._btn._enabled is True

    def test_freeze_tolerates_destroyed_widgets(self, loaded_app):
        # Every branch is individually try/except'd because a close can race
        # the worker; completing the rest of the pass is the contract.
        app, _qcx = loaded_app
        app._browse_btn.destroy(); app._out.destroy(); app._pw.destroy()
        app._freeze()
        assert app._btn._enabled is False
        app._thaw()
        assert app._btn._enabled is True

    def test_freeze_survives_a_share_panel_disappearing(self, shamir_app):
        app, _meta, _shares = shamir_app
        app._file_card.destroy()
        app._inputs[0].destroy()
        app._share_btns[0].destroy()
        app._freeze()
        assert app._verify_btn._enabled is False
        app._thaw()
        assert app._verify_btn._enabled is True
        assert app._inputs[1]._paste_btn._enabled is True, "the survivor is thawed"

    def test_freeze_survives_a_code_field_disappearing(self, shamir_app):
        app, _meta, _shares = shamir_app
        app._imode.set("raw"); app.update()
        app._file_card.destroy()
        app._entries[0].destroy()
        app._share_btns[0].destroy()
        app._freeze()
        assert str(app._entries[1].cget("state")) == "disabled"
        app._thaw()
        assert str(app._entries[1].cget("state")) == "normal"


@requires_tkinter
class TestProgressBar:
    """Each run builds its own bar so the dots match what will actually happen,
    and the raw core string never reaches the label."""

    def test_a_new_bar_has_one_dot_per_stage(self, loaded_app):
        from quantacrypt.ui.decryptor import _stages_for
        app, _qcx = loaded_app
        stages = _stages_for("shamir", verify=True)
        bar = app._new_prog(stages)
        assert len(bar._dot_cvs) == len(stages)
        assert app._run_stages == stages
        assert bar.winfo_manager() == "pack"

    def test_a_bar_that_is_already_gone_does_not_block_the_new_one(self, loaded_app):
        from quantacrypt.ui.decryptor import _stages_for
        app, _qcx = loaded_app
        app._prog.destroy()               # the window was torn down mid-run
        bar = app._new_prog(_stages_for("single"))
        assert bar.winfo_exists() and app._prog is bar

    def test_the_old_bar_is_torn_down(self, loaded_app):
        from quantacrypt.ui.decryptor import _stages_for
        app, _qcx = loaded_app
        first = app._prog
        app._new_prog(_stages_for("single"))
        assert app._prog is not first
        assert not first.winfo_exists()

    def test_progress_messages_become_friendly_labels(self, loaded_app):
        from quantacrypt.ui.decryptor import _stages_for
        app, _qcx = loaded_app
        app._new_prog(_stages_for("single"))
        app._prog.start()
        app._busy = True
        try:
            app._prog_cb("Decrypting payload... 40%")
            _pump(app, 0.2)
            assert app._prog._stage_lbl.cget("text").startswith("Decrypting file  40%")
        finally:
            app._busy = False

    def test_an_unknown_message_is_ignored(self, loaded_app):
        from quantacrypt.ui.decryptor import _stages_for
        app, _qcx = loaded_app
        app._new_prog(_stages_for("single"))
        app._prog.start()
        app._busy = True
        try:
            before = app._prog._stage_lbl.cget("text")
            app._prog_cb("polishing the bits")
            _pump(app, 0.15)
            assert app._prog._stage_lbl.cget("text") == before
        finally:
            app._busy = False

    def test_progress_after_the_run_finished_is_dropped(self, loaded_app):
        from quantacrypt.ui.decryptor import _stages_for
        app, _qcx = loaded_app
        app._new_prog(_stages_for("single"))
        app._prog.start()
        app._busy = False                    # the worker returned already
        before = app._prog._stage_lbl.cget("text")
        app._prog_cb("argon2id")
        _pump(app, 0.15)
        assert app._prog._stage_lbl.cget("text") == before


# ═════════════════════════════════════════════════════════════════════════════
# The decrypt flow, end to end
# ═════════════════════════════════════════════════════════════════════════════


@requires_tkinter
class TestDecryptFlow:
    """A real decryption through the real core, driven from the real form."""

    def test_a_correct_password_writes_the_original_file(self, loaded_app, tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "out"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        app._pw.insert(0, PW)
        app._start()
        assert _pump_until(app, lambda: not app._busy)

        written = os.path.join(str(out), "data.bin")
        assert os.path.isfile(written)
        assert open(written, "rb").read() == b"hello decrypt" * 200

        texts = _widget_texts(app._results)
        assert f"{ICON['ok']}  Decrypted successfully" in texts
        assert written in texts
        assert app._wiz._active == len(app.STEPS)
        assert app._btn._enabled is False, "success must not invite a second run"
        assert app._btn.cget("text").startswith("Decrypt again")
        assert app._pw.get() == "", "the password is cleared after success"
        assert app._orig == "data.bin"

    def test_the_file_is_added_to_the_recent_list(self, loaded_app, tmp_path):
        app, qcx = loaded_app
        out = tmp_path / "out2"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        app._pw.insert(0, PW)
        app._start()
        assert _pump_until(app, lambda: not app._busy)
        assert qcx in [p for p, _ in RecentFiles.load()]

    def test_a_second_run_never_overwrites_the_first_output(self, loaded_app,
                                                            tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "out3"; out.mkdir()
        (out / "data.bin").write_bytes(b"do not clobber me")
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        app._pw.insert(0, PW)
        app._start()
        assert _pump_until(app, lambda: not app._busy)

        assert (out / "data.bin").read_bytes() == b"do not clobber me"
        assert (out / "data_2.bin").exists()
        assert any("already existed there" in t for t in _widget_texts(app._results))

    def test_a_wrong_password_reports_it_and_writes_nothing(self, loaded_app,
                                                            tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "out4"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        app._pw.insert(0, "definitely-not-it")
        app._start()
        assert _pump_until(app, lambda: not app._busy)

        assert os.listdir(str(out)) == [], "no partial output may survive"
        assert app._err.cget("text").startswith("Wrong password")
        assert app._pw_failures == 1
        assert app._wiz._active == 2
        assert app._btn._enabled is True, "the form must be usable again"

    def test_three_wrong_passwords_add_the_no_recovery_note(self, loaded_app,
                                                            tmp_path):
        from quantacrypt.ui.decryptor import NO_RECOVERY_NOTE
        app, _qcx = loaded_app
        out = tmp_path / "out5"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        for i in range(3):
            app._pw.delete(0, "end"); app._pw.insert(0, f"wrong-{i}")
            app._start()
            assert _pump_until(app, lambda: not app._busy)
        assert app._pw_failures == 3
        assert app._err_detail.cget("text") == NO_RECOVERY_NOTE

    def test_validation_failure_never_starts_a_worker(self, loaded_app, tmp_path):
        app, _qcx = loaded_app
        app._out.delete(0, "end")
        app._pw.insert(0, PW)
        app._start()
        assert app._busy is False
        assert app._err.cget("text") == "Choose a folder to save the decrypted file in"
        assert app._results.winfo_children() == []

    def test_a_second_start_while_busy_is_ignored(self, loaded_app, tmp_path):
        """The guard is what stops a re-entrant run: without it ``_begin``
        would wipe the status line, empty the results card and launch a second
        worker over the top of the one already running."""
        import tkinter as tk
        app, _qcx = loaded_app
        out = tmp_path / "reentrant"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        app._pw.insert(0, PW)                       # a form that WOULD validate
        tk.Label(app._results, text="previous result").pack()
        app._set_status("first run still going")
        first_bar = app._prog

        app._busy = True
        try:
            app._start()
            app._start_verify()
            assert app._verifying is False, "no second run was configured"
            assert app._prog is first_bar, "the running bar was not replaced"
            assert "previous result" in _widget_texts(app._results)
            assert app._err.cget("text") == "first run still going"
            assert os.listdir(str(out)) == []
        finally:
            app._busy = False

    def test_a_shamir_file_decrypts_from_two_phrases(self, shamir_app, tmp_path):
        app, _meta, shares = shamir_app
        out = tmp_path / "sout"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        for i in range(2):
            app._inputs[i].set_words(_mnemonic_for(shares[i]).split())
        app._start()
        assert _pump_until(app, lambda: not app._busy)
        assert (out / "secret.bin").read_bytes() == b"shamir payload " * 40
        assert any("Share inputs were cleared after decryption." in t
                   for t in _widget_texts(app._results))
        assert all(not inp.has_input() for inp in app._inputs)

    def test_duplicate_shares_are_caught_before_the_worker_starts(self, shamir_app,
                                                                  tmp_path):
        app, _meta, shares = shamir_app
        out = tmp_path / "sout2"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        for i in range(2):
            app._inputs[i].set_words(_mnemonic_for(shares[0]).split())
        app._start()
        assert app._busy is False
        assert "are the same share" in app._err.cget("text")
        assert os.listdir(str(out)) == []

    def test_a_checksum_failure_gets_the_wrong_shares_copy(self, shamir_app,
                                                           tmp_path):
        from quantacrypt.ui.decryptor import get_wl
        app, _meta, _shares = shamir_app
        out = tmp_path / "sout3"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        app._inputs[0].set_words(_checksum_bad_words(get_wl()))
        app._inputs[1].set_words(_checksum_bad_words(get_wl()))
        app._start()
        assert app._busy is False
        assert app._err.cget("text") == app._shares_wrong_copy()
        assert "Checksum" not in app._err.cget("text"), "no raw crypto wording"

    def test_wrong_shares_report_the_swap_advice(self, shamir_app, shamir_sample,
                                                 tmp_path, tmp_path_factory):
        """Shares from a *different* file decode fine but recover the wrong key."""
        app, _meta, _shares = shamir_app
        other_dir = tmp_path_factory.mktemp("other_shamir")
        _enc, _m, other_shares, _fk = _make_qcx(other_dir, b"different", n=3, k=2)
        out = tmp_path / "sout4"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        for i in range(2):
            app._inputs[i].set_words(_mnemonic_for(other_shares[i]).split())
        app._start()
        assert _pump_until(app, lambda: not app._busy)
        assert app._err.cget("text") == app._shares_wrong_copy()
        assert os.listdir(str(out)) == []

    def test_a_corrupt_payload_is_never_called_a_wrong_password(self, loaded_app,
                                                                tmp_path):
        app, qcx = loaded_app
        # Flip a byte inside the first payload chunk: the key still proves out
        # (envelope + HMAC), so the failure is damage, not a bad credential.
        data = bytearray(open(qcx, "rb").read())
        offset = app._meta["payload_offset"] + 16
        data[offset] ^= 0xFF
        open(qcx, "wb").write(bytes(data))

        out = tmp_path / "out6"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        app._pw.insert(0, PW)
        app._start()
        assert _pump_until(app, lambda: not app._busy)
        assert "Wrong password" not in app._err.cget("text")
        assert "damaged" in app._err.cget("text")
        assert app._pw_failures == 0
        assert os.listdir(str(out)) == []

    def test_clearing_the_password_lifts_the_disabled_state_first(self, loaded_app):
        """A disabled Entry silently ignores delete(), so the frozen field has
        to be re-enabled around the wipe."""
        app, _qcx = loaded_app
        app._pw.insert(0, "leftover")
        app._pw.config(state="disabled")
        app._clear_pw()
        assert app._pw.get() == ""
        assert str(app._pw.cget("state")) == "disabled", "the freeze is restored"

    def test_clearing_a_torn_down_password_field_is_harmless(self, loaded_app):
        """``_clear_pw`` is an ``after`` hop from the worker, so it can land
        after a close.  Swallowing is the contract — and the read it starts
        with genuinely raises on a destroyed field."""
        import tkinter as tk
        app, _qcx = loaded_app
        app._pw.insert(0, "leftover")
        app._pw.destroy()
        with pytest.raises(tk.TclError):
            app._pw.cget("state")
        assert app._clear_pw() is None


@requires_tkinter
class TestVerifyFlow:
    """"Verify key only" proves the credentials and writes nothing."""

    def test_a_correct_password_verifies_without_writing(self, loaded_app, tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "vout"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        app._pw.insert(0, PW)
        app._start_verify()
        assert _pump_until(app, lambda: not app._busy)

        assert os.listdir(str(out)) == []
        texts = _widget_texts(app._results)
        assert f"{ICON['ok']}  Key verified. Your credentials are correct" in texts
        assert app._wiz._active == 2, "verify does not complete the wizard"
        assert app._btn._enabled is True

    def test_a_wrong_password_fails_verification(self, loaded_app, tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "vout2"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        app._pw.insert(0, "nope-nope-nope")
        app._start_verify()
        assert _pump_until(app, lambda: not app._busy)
        assert app._err.cget("text").startswith("Wrong password")
        assert app._results.winfo_children() == []

    def test_verify_then_decrypt_reuses_the_typed_password(self, loaded_app,
                                                           tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "vout3"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        app._pw.insert(0, PW)
        app._start_verify()
        assert _pump_until(app, lambda: not app._busy)

        app._reset_and_decrypt()
        assert _pump_until(app, lambda: not app._busy)
        assert (out / "data.bin").exists()

    def test_verify_validation_errors_are_shown(self, loaded_app):
        app, _qcx = loaded_app
        app._out.delete(0, "end")
        app._start_verify()
        assert app._busy is False
        assert app._err.cget("text") == "Choose a folder to save the decrypted file in"

    def test_a_cancel_landing_during_key_derivation_stops_before_the_file(
            self, loaded_app, monkeypatch):
        """Key derivation cannot be interrupted once Argon2id is running, so
        the worker re-checks before it goes on to read the payload."""
        app, _qcx = loaded_app
        read = []
        monkeypatch.setattr(corepkg, "derive_final_key",
                            lambda meta, **kw: (b"k" * 32, b"h" * 32))
        monkeypatch.setattr(corepkg, "verify_first_chunk",
                            lambda *a, **k: read.append(1))
        app._busy = True
        app._verifying = True
        app._cancel = True
        app._verify_run(PW, None)
        assert _pump_until(app, lambda: not app._busy)
        assert read == [], "the payload must never be touched after a cancel"
        assert app._err.cget("text") == "Verification cancelled. Nothing was written."

    def test_a_cancel_before_the_key_check_writes_nothing(self, loaded_app, tmp_path):
        app, _qcx = loaded_app
        app._busy = True
        app._verifying = True
        app._cancel = True                 # the worker's own post-derive check
        app._verify_run(PW, None)
        assert _pump_until(app, lambda: not app._busy)
        assert app._err.cget("text") == "Verification cancelled. Nothing was written."
        assert app._results.winfo_children() == []


@requires_tkinter
class TestCancellation:
    """Cancel is co-operative: the worker raises at the next checkpoint and the
    UI says plainly that nothing was written."""

    def test_requesting_a_cancel_flags_the_worker_and_says_so(self, loaded_app):
        app, _qcx = loaded_app
        app._busy = True
        try:
            app._request_cancel()
            assert app._cancel is True
            assert app._cancel_btn._enabled is False
            assert app._err.cget("text") == "Cancelling. Finishing the current step…"
        finally:
            app._busy = False
            app._cancel = False

    def test_cancel_still_flags_the_worker_when_its_button_is_gone(self,
                                                                   loaded_app):
        """Disabling the button is cosmetic; the flag is the part the worker
        reads, so losing the button must not lose the cancel."""
        import tkinter as tk
        app, _qcx = loaded_app
        app._busy = True
        try:
            app._cancel_btn.destroy()
            with pytest.raises(tk.TclError):
                app._cancel_btn.enable(False)     # what _request_cancel survives
            app._request_cancel()
            assert app._cancel is True
            assert app._err.cget("text") == "Cancelling. Finishing the current step…"
        finally:
            app._busy = False
            app._cancel = False

    def test_cancelling_when_nothing_runs_is_ignored(self, loaded_app):
        app, _qcx = loaded_app
        app._request_cancel()
        assert app._cancel is False
        assert app._err.cget("text") == ""

    def test_a_cancelled_decryption_leaves_no_output(self, loaded_app, tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "cout"; out.mkdir()
        app._busy = True
        app._verifying = False
        app._cancel = True                 # derive_final_key checks after Argon2id
        app._run(str(out), PW)
        assert _pump_until(app, lambda: not app._busy)
        assert app._err.cget("text") == "Decryption cancelled. Nothing was written."
        assert os.listdir(str(out)) == []
        assert app._prog.winfo_manager() == "", "the bar is taken down"
        assert app._btn._enabled is True

    def test_the_cancel_button_reaches_a_running_worker(self, loaded_app, tmp_path,
                                                        monkeypatch):
        """The Cancel button, the ``_cancel`` flag and the worker's
        ``cancel_check`` closure have to be wired to each other."""
        app, _qcx = loaded_app
        out = tmp_path / "cout2"; out.mkdir()
        seen = {}

        def _spin(path, out_dir, *, password=None, shares=None, progress=None,
                  cancel_check=None):
            seen["progress"] = progress
            deadline = _time.monotonic() + 10
            while _time.monotonic() < deadline:
                if cancel_check():
                    raise cc.CancelledOperation()
                _time.sleep(0.01)
            raise AssertionError("cancel never reached the worker")

        monkeypatch.setattr(corepkg, "decrypt_qcx", _spin)
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        app._pw.insert(0, PW)
        app._start()
        assert app._busy is True
        app._cancel_btn._fire()
        assert _pump_until(app, lambda: not app._busy)
        assert app._err.cget("text") == "Decryption cancelled. Nothing was written."
        assert seen["progress"] == app._prog_cb   # the bound method, not a wrapper


@requires_tkinter
class TestSuccessCard:
    """What ``_done`` renders.  It is called directly here so the card's own
    branches (rename note, folder archive, timestamps) can be pinned without
    manufacturing each situation through a real decryption."""

    def _prime(self, app):
        """Put the app in the state a worker leaves behind."""
        app._busy = True
        app._prog.start()

    def test_the_card_shows_the_size_the_path_and_the_original_name(self,
                                                                    loaded_app,
                                                                    tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "report_2.pdf"
        out.write_bytes(b"z" * 4096)
        self._prime(app)
        app._done(str(out), 4096, fname="report.pdf", sz=4096, ts=1_600_000_000,
                  renamed=True)
        texts = _widget_texts(app._results)
        assert "4.1 KB" in texts                      # 4096 B, decimal units
        assert str(out) in texts
        assert "report.pdf" in texts
        assert any("already existed there" in t and "report_2.pdf" in t
                   for t in texts)
        assert any(t.startswith("Original: 4.1 KB") and "Encrypted:" in t
                   for t in texts)

    def test_the_filename_line_is_dropped_when_it_matches_the_output(self,
                                                                     loaded_app,
                                                                     tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "same.bin"
        out.write_bytes(b"q" * 16)
        self._prime(app)
        app._done(str(out), 16, fname="same.bin")
        assert _widget_texts(app._results).count("same.bin") == 0
        assert str(out) in _widget_texts(app._results)

    def test_a_traversal_shaped_name_is_shown_as_a_basename(self, loaded_app,
                                                            tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "restored.bin"
        out.write_bytes(b"z" * 10)
        self._prime(app)
        app._done(str(out), 10, fname="../../../etc/passwd", sz=10, ts=0)
        texts = _widget_texts(app._results)
        assert "passwd" in texts
        assert not any(".." in t for t in texts)

    def test_without_a_recovered_name_the_output_basename_is_used(self,
                                                                  loaded_app,
                                                                  tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "anon.bin"
        out.write_bytes(b"w" * 8)
        self._prime(app)
        app._done(str(out), 8)
        assert app._orig is None
        assert "Hidden; shown after decryption" in _widget_texts(app._info_wrap)

    def test_an_unrenderable_timestamp_only_drops_that_fragment(self, loaded_app,
                                                                tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "odd.bin"
        out.write_bytes(b"w" * 8)
        self._prime(app)
        app._done(str(out), 8, fname="odd.bin", sz=8, ts=10 ** 20)
        assert any(t == "Original: 8 B" for t in _widget_texts(app._results))

    def test_a_folder_archive_offers_extraction_instead_of_open(self, loaded_app,
                                                                tmp_path):
        app, _qcx = loaded_app
        z = tmp_path / "docs.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("docs/a.txt", "alpha")
        self._prime(app)
        app._done(str(z), z.stat().st_size, fname="docs.zip")
        texts = _widget_texts(app._results)
        assert "Extract folder" in texts and "Open file" not in texts

    def test_a_plain_file_offers_open_instead_of_extraction(self, loaded_app,
                                                            tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "plain.bin"
        out.write_bytes(b"p" * 32)
        self._prime(app)
        app._done(str(out), 32, fname="plain.bin")
        texts = _widget_texts(app._results)
        assert "Open file" in texts and "Extract folder" not in texts

    def test_a_zip_named_file_that_is_not_a_zip_offers_open(self, loaded_app,
                                                            tmp_path):
        app, _qcx = loaded_app
        fake = tmp_path / "fake.zip"
        fake.write_bytes(b"not really a zip")
        self._prime(app)
        app._done(str(fake), 16, fname="fake.zip")
        assert "Open file" in _widget_texts(app._results)

    def test_a_failing_recent_files_store_does_not_break_the_card(self, loaded_app,
                                                                  tmp_path,
                                                                  monkeypatch):
        app, _qcx = loaded_app
        monkeypatch.setattr(RecentFiles, "add",
                            classmethod(lambda cls, *a, **k: (_ for _ in ()).throw(
                                OSError("disk full"))))
        out = tmp_path / "ok.bin"
        out.write_bytes(b"o" * 4)
        self._prime(app)
        app._done(str(out), 4, fname="ok.bin")
        assert f"{ICON['ok']}  Decrypted successfully" in _widget_texts(app._results)

    def test_raw_share_fields_are_wiped_after_success(self, shamir_app, tmp_path):
        app, _meta, shares = shamir_app
        app._imode.set("raw"); app.update()
        for e, s in zip(app._entries, shares):
            e.insert(0, s)
        out = tmp_path / "done.bin"
        out.write_bytes(b"d" * 4)
        self._prime(app)
        app._done(str(out), 4, fname="done.bin")
        assert all(e.get() == "" for e in app._entries)
        assert all(m.cget("text") == "" for m in app._entry_marks)
        assert any("Share inputs were cleared" in t for t in _widget_texts(app._results))

    def test_the_card_is_still_built_when_a_share_input_is_already_gone(self,
                                                                        shamir_app,
                                                                        tmp_path):
        """Wiping the credentials is best-effort — a panel destroyed by a
        racing close must not cost the user the success card."""
        app, _meta, shares = shamir_app
        app._inputs[0].set_words(_mnemonic_for(shares[0]).split())
        app._inputs[0].destroy()
        out = tmp_path / "raced.bin"
        out.write_bytes(b"r" * 4)
        self._prime(app)
        app._done(str(out), 4, fname="raced.bin")
        assert f"{ICON['ok']}  Decrypted successfully" in _widget_texts(app._results)

    def test_a_destroyed_code_field_costs_the_user_the_success_card(self,
                                                                    shamir_app,
                                                                    tmp_path):
        """BUG (documented, not fixed here): ``_done`` wipes each code field
        inside a try/except but then calls ``_update_share_counter``, which
        reads every field unguarded — so one destroyed field aborts the card
        for a decryption whose output is already safely on disk."""
        import tkinter as tk
        app, _meta, shares = shamir_app
        app._imode.set("raw"); app.update()
        app._entries[0].insert(0, shares[0])
        app._entries[0].destroy()
        out = tmp_path / "raced2.bin"
        out.write_bytes(b"r" * 4)
        self._prime(app)
        with pytest.raises(tk.TclError):
            app._done(str(out), 4, fname="raced2.bin")
        assert out.exists(), "the decrypted file itself is unaffected"
        assert app._results.winfo_children() == [], "…but no card was built"

    def test_a_password_file_gets_no_share_note(self, loaded_app, tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "pw.bin"
        out.write_bytes(b"p" * 4)
        self._prime(app)
        app._done(str(out), 4, fname="pw.bin")
        assert not any("Share inputs were cleared" in t
                       for t in _widget_texts(app._results))


@requires_tkinter
class TestReveal:
    """"Show in Finder" degrades to a status line when there is no file
    manager to hand off to."""

    def test_a_working_file_manager_says_nothing(self, loaded_app, tmp_path,
                                                 monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        seen = []
        monkeypatch.setattr(dec, "reveal_path", lambda p: seen.append(p) or True)
        app._set_status("earlier message")
        app._reveal(str(tmp_path))
        assert seen == [str(tmp_path)], "the exact path is handed over"
        assert app._err.cget("text") == "earlier message", \
            "a successful reveal must not talk over what was already there"

    def test_a_missing_file_manager_prints_the_path(self, loaded_app, tmp_path,
                                                    monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        monkeypatch.setattr(dec, "reveal_path", lambda p: False)
        app._reveal(str(tmp_path / "thing.bin"))
        assert "Couldn't open the file manager" in app._err.cget("text")
        assert str(tmp_path / "thing.bin") in app._err.cget("text")


# ═════════════════════════════════════════════════════════════════════════════
# Extract folder
# ═════════════════════════════════════════════════════════════════════════════


@requires_tkinter
class TestExtractFolder:
    """A folder-encrypted .qcx decrypts to a zip; "Extract folder" unpacks it
    into a directory that does not exist yet, and never over one that does."""

    def _zip(self, tmp_path, name="docs.zip", members=(("docs/a.txt", "alpha"),)):
        z = tmp_path / name
        with zipfile.ZipFile(z, "w") as zf:
            for n, body in members:
                zf.writestr(n, body)
        return str(z)

    def test_extraction_writes_the_tree_and_reports_where(self, loaded_app,
                                                          tmp_path, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        d = _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(dec, "reveal_path", lambda p: True)
        z = self._zip(tmp_path, members=[("docs/a.txt", "alpha"),
                                         ("docs/sub/b.txt", "beta")])
        app._extract_folder(z)
        assert _pump_until(app, lambda: not app._busy)

        dest = tmp_path / "docs"
        assert (dest / "a.txt").read_text() == "alpha"
        assert (dest / "sub" / "b.txt").read_text() == "beta"
        assert d.alert_titles == ["Folder extracted"]
        assert str(dest) in app._err.cget("text")
        assert app._btn._enabled is False, "the post-decrypt state is restored"

    def test_a_second_extraction_goes_beside_the_first(self, loaded_app, tmp_path,
                                                       monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        d = _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(dec, "reveal_path", lambda p: True)
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "mine.txt").write_text("keep")
        z = self._zip(tmp_path)
        app._extract_folder(z)
        assert _pump_until(app, lambda: not app._busy)

        assert (tmp_path / "docs" / "mine.txt").read_text() == "keep"
        assert (tmp_path / "docs_2" / "a.txt").read_text() == "alpha"
        assert "already existed" in d.alerts[-1][1]

    def test_a_multi_root_archive_is_named_after_the_zip(self, loaded_app, tmp_path,
                                                         monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(dec, "reveal_path", lambda p: True)
        z = self._zip(tmp_path, name="bundle.zip",
                      members=[("one/a.txt", "a"), ("two/b.txt", "b")])
        app._extract_folder(z)
        assert _pump_until(app, lambda: not app._busy)
        assert (tmp_path / "bundle" / "one" / "a.txt").read_text() == "a"
        assert (tmp_path / "bundle" / "two" / "b.txt").read_text() == "b"

    def test_directory_entries_are_created(self, loaded_app, tmp_path, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(dec, "reveal_path", lambda p: True)
        z = tmp_path / "withdirs.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("root/", "")
            zf.writestr("root/empty/", "")
            zf.writestr("root/a.txt", "a")
        app._extract_folder(str(z))
        assert _pump_until(app, lambda: not app._busy)
        assert (tmp_path / "root" / "empty").is_dir()
        assert (tmp_path / "root" / "a.txt").read_text() == "a"

    def test_an_unreadable_archive_is_reported_and_nothing_is_made(self, loaded_app,
                                                                   tmp_path,
                                                                   monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        d = _Dialogs(monkeypatch, dec)
        bad = tmp_path / "broken.zip"
        bad.write_bytes(b"PK\x03\x04 nope")
        app._extract_folder(str(bad))
        assert d.alert_titles == ["Extraction failed"]
        assert app._busy is False
        assert not (tmp_path / "broken").exists()

    def test_an_escaping_member_stops_everything(self, loaded_app, tmp_path,
                                                 monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        d = _Dialogs(monkeypatch, dec)
        z = self._zip(tmp_path, name="evil.zip",
                      members=[("ok.txt", "fine"), ("../escape.txt", "bad")])
        app._extract_folder(z)
        assert d.alert_titles == ["Archive not extracted"]
        assert "../escape.txt" in d.alerts[0][1]
        assert not (tmp_path.parent / "escape.txt").exists()
        assert app._busy is False

    def test_an_oversized_archive_is_confirmed_first(self, loaded_app, tmp_path,
                                                     monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        d = _Dialogs(monkeypatch, dec, answer=False)
        monkeypatch.setattr(dec, "_EXTRACT_MAX_ENTRIES", 1)
        z = self._zip(tmp_path, members=[("docs/a.txt", "a"), ("docs/b.txt", "b")])
        app._extract_folder(z)
        assert d.confirms and d.confirms[0][0] == "Large archive"
        assert not (tmp_path / "docs").exists(), "declining extracts nothing"

        d.answer = True
        monkeypatch.setattr(dec, "reveal_path", lambda p: True)
        app._extract_folder(z)
        assert _pump_until(app, lambda: not app._busy)
        assert (tmp_path / "docs" / "a.txt").read_text() == "a"

    def test_an_archive_past_the_byte_cap_is_confirmed_first(self, loaded_app,
                                                             tmp_path, monkeypatch):
        """The gate is entries-OR-bytes; the entry side is covered above, this
        is the byte side, and the prompt has to quote the expanded size."""
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        d = _Dialogs(monkeypatch, dec, answer=False)
        monkeypatch.setattr(dec, "_EXTRACT_MAX_BYTES", 4)
        z = self._zip(tmp_path, name="fat.zip", members=[("fat/a.txt", "abcdefgh")])
        app._extract_folder(z)
        assert d.confirms and d.confirms[0][0] == "Large archive"
        assert "8 B" in d.confirms[0][1] and "1 entries" in d.confirms[0][1]
        assert not (tmp_path / "fat").exists(), "declining extracts nothing"
        assert app._busy is False

    def test_an_archive_with_no_members_makes_an_empty_folder(self, loaded_app,
                                                              tmp_path, monkeypatch):
        """Zero-iteration case for the member loop: the destination is still
        created and reported, not silently skipped."""
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        d = _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(dec, "reveal_path", lambda p: True)
        z = tmp_path / "hollow.zip"
        with zipfile.ZipFile(z, "w"):
            pass
        app._extract_folder(str(z))
        assert _pump_until(app, lambda: not app._busy)
        dest = tmp_path / "hollow"
        assert dest.is_dir() and list(dest.iterdir()) == []
        assert d.alert_titles == ["Folder extracted"]
        assert str(dest) in app._err.cget("text")

    def test_a_single_member_archive_extracts_that_one_file(self, loaded_app,
                                                            tmp_path, monkeypatch):
        """One-iteration case, and the only-root branch of the naming rule."""
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(dec, "reveal_path", lambda p: True)
        z = self._zip(tmp_path, name="solo.zip",
                      members=[("solo/only file.txt", "just me")])
        app._extract_folder(z)
        assert _pump_until(app, lambda: not app._busy)
        assert (tmp_path / "solo" / "only file.txt").read_text() == "just me"

    def test_a_lone_top_level_file_lands_inside_a_folder_named_after_the_zip(
            self, loaded_app, tmp_path, monkeypatch):
        """A zip holding one file at its top has the one-root shape of a
        folder archive, but stripping that "root" would leave nothing to
        write and an empty directory of the file's name."""
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        d = _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(dec, "reveal_path", lambda p: True)
        z = self._zip(tmp_path, name="notes.zip", members=[("readme.txt", "hello")])
        app._extract_folder(z)
        assert _pump_until(app, lambda: not app._busy)
        assert (tmp_path / "notes" / "readme.txt").read_text() == "hello"
        assert not (tmp_path / "readme.txt").exists()
        assert d.alert_titles == ["Folder extracted"]

    def test_a_sibling_that_merely_starts_with_the_root_name_keeps_it(
            self, loaded_app, tmp_path, monkeypatch):
        """The strip is a path component, not a string prefix: "docs-old/b"
        under a "docs" root must not come out as "-old/b"."""
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(dec, "reveal_path", lambda p: True)
        z = self._zip(tmp_path, name="mixed.zip",
                      members=[("docs/a.txt", "alpha"), ("docs-old/b.txt", "beta"),
                               ("docsfile", "gamma")])
        dest = str(tmp_path / "out-sibling")
        app._busy = True
        app._extracting = True
        app._cancel = False
        app._extract_run(z, dest, "docs", 20, False)
        assert _pump_until(app, lambda: not app._busy)
        assert (tmp_path / "out-sibling" / "a.txt").read_text() == "alpha"
        assert (tmp_path / "out-sibling" / "docs-old" / "b.txt").read_text() == "beta"
        assert (tmp_path / "out-sibling" / "docsfile").read_text() == "gamma"
        assert not (tmp_path / "out-sibling" / "-old").exists()

    def test_extracted_files_and_folders_are_private(self, loaded_app, tmp_path,
                                                     monkeypatch):
        """The zip came out of a 0600 plaintext; the tree it expands to must
        not be widened to the process umask."""
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(dec, "reveal_path", lambda p: True)
        # No directory entry for x/ or x/y/: those are the levels os.makedirs
        # would have left at the umask.
        z = self._zip(tmp_path, name="perm.zip",
                      members=[("perm/a.txt", "a"), ("perm/sub/b.txt", "b"),
                               ("perm/empty/", ""), ("perm/x/y/z.txt", "z")])
        app._extract_folder(z)
        assert _pump_until(app, lambda: not app._busy)
        dest = tmp_path / "perm"
        for d in (dest, dest / "sub", dest / "empty", dest / "x", dest / "x" / "y"):
            assert os.stat(d).st_mode & 0o777 == 0o700, d
        for f in (dest / "a.txt", dest / "sub" / "b.txt", dest / "x" / "y" / "z.txt"):
            assert os.stat(f).st_mode & 0o777 == 0o600, f

    def test_the_extracted_tree_is_quarantined(self, loaded_app, tmp_path,
                                               monkeypatch):
        """Same rule as the core's decrypted output: the folder and every
        file in it are stamped so Gatekeeper looks at an .app inside."""
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        _Dialogs(monkeypatch, dec)
        monkeypatch.setattr(dec, "reveal_path", lambda p: True)
        stamped = []
        monkeypatch.setattr(corepkg, "_mark_quarantined", stamped.append)
        z = self._zip(tmp_path, name="q.zip",
                      members=[("q/a.txt", "a"), ("q/sub/b.txt", "b")])
        app._extract_folder(z)
        assert _pump_until(app, lambda: not app._busy)
        dest = tmp_path / "q"
        assert set(stamped) == {str(dest), str(dest / "a.txt"),
                                str(dest / "sub" / "b.txt")}

    def test_a_duplicate_entry_is_refused_rather_than_overwritten(
            self, loaded_app, tmp_path, monkeypatch):
        """The destination is this run's own fresh tree, so a name that
        already exists can only be the archive repeating itself."""
        import warnings
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        d = _Dialogs(monkeypatch, dec)
        z = tmp_path / "twice.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")           # zipfile's "Duplicate name"
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("twice/a.txt", "first")
                zf.writestr("twice/a.txt", "second")
        dest = str(tmp_path / "out-twice")
        app._busy = True
        app._extracting = True
        app._cancel = False
        app._extract_run(str(z), dest, "twice", 20, False)
        assert _pump_until(app, lambda: not app._busy)
        assert not os.path.exists(dest)
        assert d.alert_titles == ["Extraction failed"]

    def test_extraction_is_refused_while_something_else_runs(self, loaded_app,
                                                             tmp_path, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        _Dialogs(monkeypatch, dec)
        z = self._zip(tmp_path)
        app._busy = True
        try:
            app._extract_folder(z)
            assert not (tmp_path / "docs").exists()
        finally:
            app._busy = False

    def test_a_cancel_removes_the_half_written_directory(self, loaded_app, tmp_path):
        app, _qcx = loaded_app
        z = self._zip(tmp_path, members=[(f"docs/f{i}.txt", "x" * 100)
                                         for i in range(20)])
        dest = str(tmp_path / "out-cancel")
        app._busy = True
        app._extracting = True
        app._cancel = True
        app._extract_run(z, dest, "docs", 2000, False)
        assert _pump_until(app, lambda: not app._busy)
        assert not os.path.exists(dest), "nothing partial may survive"
        assert app._err.cget("text") == "Extraction cancelled. Nothing was kept."

    def test_a_cancel_landing_mid_file_is_caught_inside_the_write_loop(self,
                                                                       loaded_app,
                                                                       tmp_path,
                                                                       monkeypatch):
        """The between-members check cannot help a single huge member: Cancel
        has to be honoured between chunks too, and still take the whole
        half-written destination with it.  The flag is flipped from the
        per-file directory creation so it lands *after* that member's
        loop-top check and *before* its first chunk is written."""
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        z = tmp_path / "onebig.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("onebig/big.bin", b"z" * (3 << 20))
        dest = str(tmp_path / "out-midcancel")

        real_mkdirs = dec._makedirs_private

        def _flip(path):                  # per entry only; the top one is makedirs
            app._cancel = True
            return real_mkdirs(path)

        monkeypatch.setattr(dec, "_makedirs_private", _flip)
        app._busy = True
        app._extracting = True
        app._cancel = False
        app._extract_run(str(z), dest, "onebig", 3 << 20, False)
        assert _pump_until(app, lambda: not app._busy)
        assert not os.path.exists(dest), "the half-written tree goes with it"
        assert app._err.cget("text") == "Extraction cancelled. Nothing was kept."

    def test_an_index_that_lies_about_the_size_aborts(self, loaded_app, tmp_path,
                                                      monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        d = _Dialogs(monkeypatch, dec)
        z = self._zip(tmp_path, name="liar.zip",
                      members=[("docs/big.bin", "y" * (3 << 20))])
        dest = str(tmp_path / "out-liar")
        app._busy = True
        app._extracting = True
        app._cancel = False
        app._extract_run(z, dest, "docs", 10, False)     # declared 10 bytes
        assert _pump_until(app, lambda: not app._busy)
        assert not os.path.exists(dest)
        assert "Extraction failed" in app._err.cget("text")
        assert d.alert_titles == ["Extraction failed"]

    def test_an_entry_that_escapes_the_destination_aborts_the_worker(self,
                                                                     loaded_app,
                                                                     tmp_path,
                                                                     monkeypatch):
        """The pre-flight screen already rejects these, so this is the worker's
        own second line of defence (symlinked/racy destinations)."""
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        _Dialogs(monkeypatch, dec)
        z = tmp_path / "sneak.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("docs/../../escape.txt", "bad")
        dest = str(tmp_path / "out-sneak")
        app._busy = True
        app._extracting = True
        app._cancel = False
        app._extract_run(str(z), dest, "docs", 10, False)
        assert _pump_until(app, lambda: not app._busy)
        assert not os.path.exists(dest)
        assert not (tmp_path.parent / "escape.txt").exists()

    def test_a_pre_existing_destination_is_never_removed(self, loaded_app,
                                                         tmp_path, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        _Dialogs(monkeypatch, dec)
        dest = tmp_path / "already"
        dest.mkdir()
        (dest / "mine.txt").write_text("keep me")
        z = self._zip(tmp_path)
        app._busy = True
        app._extracting = True
        app._cancel = False
        app._extract_run(z, str(dest), "docs", 10, False)
        assert _pump_until(app, lambda: not app._busy)
        assert (dest / "mine.txt").read_text() == "keep me"
        assert "appeared in" in app._err_detail.cget("text")


# ═════════════════════════════════════════════════════════════════════════════
# Reset, close and cancellation of the window itself
# ═════════════════════════════════════════════════════════════════════════════


@requires_tkinter
class TestReset:
    """"Decrypt another" must leave the window exactly as it was built."""

    def test_reset_clears_everything_the_file_put_there(self, loaded_app, tmp_path):
        from quantacrypt.ui.decryptor import (FILE_PROMPT, SEC_HINT_EMPTY,
                                              OUT_HINT_EMPTY)
        app, _qcx = loaded_app
        out = tmp_path / "rout"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        app._pw.insert(0, PW)
        app._start()
        assert _pump_until(app, lambda: not app._busy)

        app._reset()
        assert app._payload is None and app._meta is None and app._mode_val is None
        assert app._sz == 0 and app._ts == 0 and app._pw_failures == 0
        assert app._out.get() == ""
        assert app._out_hint.cget("text") == OUT_HINT_EMPTY
        assert app._results.winfo_children() == []
        assert app._info_wrap.winfo_children() == []
        assert app._inspect_row.winfo_children() == []
        assert app._verify_btn._enabled is False
        assert app._sec_label.cget("text") == "2  PASSWORD"
        assert SEC_HINT_EMPTY in _widget_texts(app._sec_wrap)
        assert FILE_PROMPT in _widget_texts(app._file_card)
        assert app._btn.cget("text") == "Open a file to begin"
        assert app._prog.winfo_manager() == ""
        assert app._wiz._active == 0
        assert app.title() == "QuantaCrypt · Decrypt"

    def test_reset_drops_the_share_mode_trace(self, shamir_app):
        app, _meta, _shares = shamir_app
        first = app._imode_trace_id
        assert first is not None
        app._reset()
        assert app._imode_trace_id is None
        assert app._inputs == [] and app._entries == []
        assert first not in {name for _, name in app._imode.trace_info()}

    def test_reset_survives_a_stale_mode_trace_id(self, shamir_app):
        """Same race as the reload, on the way out: a handler Tk has already
        reclaimed must not leave the window half-reset."""
        app, _meta, _shares = shamir_app
        app._imode_trace_id = "stale_no_such_command"
        app._reset()
        assert app._imode_trace_id is None
        assert app._payload is None and app._inputs == [] and app._entries == []
        assert app._btn.cget("text") == "Open a file to begin"
        assert app._out.get() == ""

    def test_the_form_can_be_used_again_after_a_reset(self, loaded_app, tmp_path,
                                                      qcx_sample):
        import shutil
        app, qcx = loaded_app
        app._reset()
        again = tmp_path / "again.qcx"
        shutil.copy(qcx, again)
        app._on_file(str(again))
        assert app._btn._enabled is True
        assert app._btn.cget("text").startswith("Decrypt file")


@requires_tkinter
class TestCloseGuards:
    """Closing must never drop a typed credential silently, and must never
    destroy the window out from under a running worker."""

    def test_an_untouched_window_closes_immediately(self, ui_root, tmp_path,
                                                    monkeypatch):
        dec = _quiet(monkeypatch, tmp_path)
        closed = []
        app = _make_app(ui_root, dec, closed=lambda: closed.append(1))
        _Dialogs(monkeypatch, dec, answer=False)
        app._maybe_close()
        assert closed == [1]
        assert not app.winfo_exists()

    def test_escape_closes_and_swallows_the_key(self, ui_root, tmp_path, monkeypatch):
        dec = _quiet(monkeypatch, tmp_path)
        closed = []
        app = _make_app(ui_root, dec, closed=lambda: closed.append(1))
        assert app._on_escape() == "break"
        assert closed == [1]

    def test_a_typed_password_is_confirmed_before_it_is_thrown_away(self,
                                                                    loaded_app,
                                                                    monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        d = _Dialogs(monkeypatch, dec, answer=False)
        app._pw.insert(0, "half-typed")
        app._maybe_close()
        assert d.confirms[0][0] == "Discard what you typed?"
        assert app.winfo_exists(), "declining keeps the window and the password"
        assert app._pw.get() == "half-typed"

        d.answer = True
        app._maybe_close()
        assert not app.winfo_exists()

    def test_typed_shares_are_confirmed_too(self, shamir_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, shares = shamir_app
        d = _Dialogs(monkeypatch, dec, answer=False)
        app._inputs[0].set_words(_mnemonic_for(shares[0]).split()[:3])
        app._maybe_close()
        assert d.confirms[0][0] == "Discard what you typed?"
        assert app.winfo_exists()

    def test_typed_codes_are_confirmed_too(self, shamir_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _meta, _shares = shamir_app
        d = _Dialogs(monkeypatch, dec, answer=False)
        app._imode.set("raw"); app.update()
        app._entries[1].insert(0, "QCSHARE-partial")
        app._maybe_close()
        assert d.confirms[0][0] == "Discard what you typed?"
        assert app.winfo_exists()

    def test_a_torn_down_password_field_does_not_block_the_close(self, loaded_app,
                                                                 monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        _Dialogs(monkeypatch, dec, answer=False)
        app._pw.destroy()
        assert app._has_typed_input() is False

    def test_closing_without_a_launcher_quits_the_app(self, ui_root, tmp_path,
                                                      monkeypatch):
        """With no launcher to go back to, closing the decryptor takes its
        master down with it.  A stand-in Toplevel plays the master here so the
        assertion does not have to tear down the shared root."""
        import tkinter as tk
        dec = _quiet(monkeypatch, tmp_path)
        holder = tk.Toplevel(ui_root)
        holder.geometry("100x100-4000-4000")
        app = dec.DecryptorApp(holder, on_close=None)
        app.geometry("620x780-4000-4000")
        app.update()
        app._close()
        assert not app.winfo_exists()
        assert not holder.winfo_exists(), "the last window closes the app"

    def test_escape_while_busy_is_a_cancel_request_not_a_discard_prompt(self,
                                                                        loaded_app,
                                                                        monkeypatch):
        """The typed password is still in the form, but a run is in flight —
        asking "discard what you typed?" would be the wrong question."""
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        d = _Dialogs(monkeypatch, dec, answer=False)
        app._pw.insert(0, PW)
        app._busy = True
        try:
            app._maybe_close()
            assert d.confirms == []
            assert app.winfo_exists()
            assert app._cancel is True and app._close_pending is True
        finally:
            app._busy = False
            app._close_pending = False
            app._cancel = False

    def test_closing_while_busy_asks_the_worker_to_stop_first(self, loaded_app):
        app, _qcx = loaded_app
        app._busy = True
        try:
            app._close()
            assert app.winfo_exists(), "the window must outlive the worker"
            assert app._close_pending is True and app._cancel is True
            assert app._cancel_btn._enabled is False
            assert app._err.cget("text").startswith("Cancelling.")
        finally:
            app._busy = False
            app._close_pending = False
            app._cancel = False

    def test_closing_while_busy_works_without_the_cancel_button(self, loaded_app):
        """A close can race the teardown of the cancel row.  The request to
        stop, the status line and the "don't destroy yet" rule all have to
        survive losing the button."""
        import tkinter as tk
        app, _qcx = loaded_app
        app._busy = True
        try:
            app._cancel_btn.destroy()
            with pytest.raises(tk.TclError):
                app._cancel_btn.enable(False)
            app._close()
            assert app.winfo_exists(), "still never destroyed under a worker"
            assert app._cancel is True and app._close_pending is True
            assert app._err.cget("text").startswith("Cancelling.")
        finally:
            app._busy = False
            app._close_pending = False
            app._cancel = False

    def test_a_second_close_request_does_not_restate_itself(self, loaded_app):
        app, _qcx = loaded_app
        app._busy = True
        try:
            app._close()
            app._set_status("something else")
            app._close()
            assert app._err.cget("text") == "something else"
        finally:
            app._busy = False
            app._close_pending = False

    def test_the_window_closes_once_the_worker_returns(self, ui_root, tmp_path,
                                                       monkeypatch, qcx_sample):
        import shutil
        dec = _quiet(monkeypatch, tmp_path)
        src, meta = qcx_sample
        qcx = tmp_path / "c.qcx"; shutil.copy(src, qcx)
        closed = []
        app = _make_app(ui_root, dec, payload={"meta": meta}, qcx_path=str(qcx),
                        closed=lambda: closed.append(1))
        app._busy = True
        app._close()
        app._busy = False                    # the worker just returned
        assert _pump_until(app, lambda: bool(closed), timeout=5.0)
        assert not app.winfo_exists()

    def test_a_worker_that_finished_first_keeps_the_result_visible(self,
                                                                   loaded_app):
        app, _qcx = loaded_app
        closed_before = app.winfo_exists()
        app._busy = True
        app._close()
        app._busy = False
        app._finished_ok = True
        assert _pump_until(app, lambda: not app._close_pending, timeout=5.0)
        assert app.winfo_exists() and closed_before
        assert app._err.cget("text") == \
            "Finished before it could be cancelled. See the result below."
        assert app._finished_ok is False

    def test_polling_stops_when_the_window_is_gone(self, ui_root, tmp_path,
                                                   monkeypatch, qcx_sample):
        """``_poll_close`` is a self-rescheduling 100 ms timer.  Waking to a
        destroyed window it has to return — falling through would reach
        ``_close`` and fire the launcher callback for a window that is already
        closed."""
        import shutil
        dec = _quiet(monkeypatch, tmp_path)
        src, meta = qcx_sample
        qcx = tmp_path / "poll.qcx"
        shutil.copy(src, qcx)
        closed = []
        app = _make_app(ui_root, dec, payload={"meta": meta}, qcx_path=str(qcx),
                        closed=lambda: closed.append(1))
        app.destroy()
        assert app._poll_close() is None
        assert closed == [], "no second close for a window that is already gone"

    def test_the_worker_hop_runs_while_open_and_is_dropped_once_closed(self,
                                                                      loaded_app):
        app, _qcx = loaded_app
        root = app._root()
        fired = []
        app._after(lambda: fired.append("open"))
        assert _pump_until(app, lambda: fired == ["open"], timeout=3.0)

        app.destroy()
        app._after(lambda: fired.append("closed"))
        _pump(root, 0.2)
        assert fired == ["open"], "a hop scheduled after the close is dropped"


@requires_tkinter
class TestShortcutsAndScrolling:
    """Cmd/Ctrl-O, Return and the mouse wheel."""

    def test_return_starts_a_decryption(self, loaded_app, tmp_path):
        app, _qcx = loaded_app
        out = tmp_path / "kout"; out.mkdir()
        app._out.delete(0, "end"); app._out.insert(0, str(out))
        app._pw.insert(0, PW)
        _press(app, f"<{_MOD}-Return>")
        assert _pump_until(app, lambda: not app._busy)
        assert (out / "data.bin").exists()

    def test_open_shortcut_calls_the_file_picker(self, loaded_app, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        app, _qcx = loaded_app
        picked = []
        monkeypatch.setattr(dec.filedialog, "askopenfilename",
                            lambda **kw: picked.append(1) or "")
        _press(app, f"<{_MOD}-o>")
        _press(app, "<Control-o>")
        assert len(picked) == 2, "both Cmd-O and Ctrl-O must reach the file card"

    def test_shortcuts_only_flash_while_busy(self, loaded_app):
        app, _qcx = loaded_app
        app._busy = True
        try:
            _press(app, f"<{_MOD}-Return>")
            assert app._err.cget("text").startswith("Busy")
            app._set_status("")
            _press(app, f"<{_MOD}-o>")
            assert app._err.cget("text").startswith("Busy")
        finally:
            app._busy = False

    def _make_scrollable(self, app):
        """Guarantee the canvas has somewhere to scroll to, whatever the
        window height the WM handed us."""
        import tkinter as tk
        tk.Frame(app._body, bg=C["bg"], height=4000).pack(fill="x")
        app.update()
        app._cv.yview_moveto(0.0)
        app.update()
        assert app._cv.yview()[1] < 1.0, "the form must overflow for this test"

    def test_the_wheel_scrolls_the_form(self, loaded_app):
        app, _qcx = loaded_app
        self._make_scrollable(app)
        app.focus_force()
        app.update()
        app.event_generate("<MouseWheel>", delta=-120)
        app.update()
        assert app._cv.yview()[0] > 0.0

    @pytest.mark.needs_real_window
    def test_the_wheel_leaves_a_dropdown_alone(self, shamir_app):
        """A word-completion dropdown is its own Toplevel; scrolling the page
        under it would move the list away from the cursor."""
        app, _meta, _shares = shamir_app
        self._make_scrollable(app)
        # The share grid's first cell was focused during the build, and its
        # deferred focus-out timer closes any list that is open when it fires —
        # so let that timer run before opening one on purpose.
        _pump(app, 0.4)
        cell = app._inputs[0]._cells[0]
        cell._v.set("aban")
        assert cell._lb is not None, "the completion list should be open"
        cell._lb.focus_force()
        app.update()
        if app.focus_get() is not cell._lb:
            pytest.skip("this display would not give the dropdown keyboard focus")
        app.event_generate("<MouseWheel>", delta=-120)
        app.update()
        assert app._cv.yview()[0] == 0.0
        cell._close()


@requires_tkinter
class TestFailureCopy:
    """``_fail`` on the real window: the credential cases get bespoke copy,
    everything else goes through the shared friendly_error vocabulary."""

    def _prime(self, app):
        app._busy = True
        app._cancel = True
        app._prog.start()

    def test_a_format_error_uses_the_helper_sentence(self, loaded_app):
        app, _qcx = loaded_app
        self._prime(app)
        app._fail(ValueError("File appears truncated"))
        assert "truncated" in app._err.cget("text")
        assert app._pw_failures == 0
        assert app._busy is False and app._cancel is False
        assert app._wiz._active == 2

    def test_a_corrupt_payload_says_the_copy_is_damaged(self, loaded_app):
        app, _qcx = loaded_app
        self._prime(app)
        app._fail(CorruptPayload("This copy can't be restored."))
        assert app._err.cget("text") == "This copy can't be restored."
        assert app._pw_failures == 0

    def test_a_pre_mapped_string_is_tolerated(self, loaded_app):
        app, _qcx = loaded_app
        self._prime(app)
        app._fail("InvalidTag")
        assert app._err.cget("text").startswith("Wrong password")
        assert app._pw_failures == 1

    def test_an_out_of_range_share_gets_the_swap_advice(self, shamir_app):
        app, _meta, _shares = shamir_app
        app._busy = True
        app._prog.start()
        app._fail(ValueError("share index out of range"))
        assert app._err.cget("text") == app._shares_wrong_copy()


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════


class TestMain:
    """``main()`` is what a self-extracting .qcx runs: a frozen build carries
    its own payload, a normal launch does not."""

    def _stub(self, monkeypatch):
        import quantacrypt.ui.decryptor as dec
        seen = {}

        class _Fake:
            def __init__(self, payload=None, qcx_path=None):
                seen["payload"] = payload
                seen["qcx_path"] = qcx_path

            def mainloop(self):
                seen["ran"] = True

        monkeypatch.setattr(dec, "DecryptorApp", _Fake)
        return dec, seen

    def test_a_normal_launch_opens_an_empty_window(self, monkeypatch):
        dec, seen = self._stub(monkeypatch)
        monkeypatch.delattr(dec.sys, "frozen", raising=False)
        dec.main()
        assert seen == {"payload": None, "qcx_path": None, "ran": True}

    def test_a_frozen_build_decrypts_itself(self, monkeypatch, tmp_path, qcx_sample):
        import shutil
        dec, seen = self._stub(monkeypatch)
        src, _meta = qcx_sample
        exe = tmp_path / "QuantaCrypt-selfdecrypt"
        shutil.copy(src, exe)
        monkeypatch.setattr(dec.sys, "frozen", True, raising=False)
        monkeypatch.setattr(dec.sys, "executable", str(exe))
        dec.main()
        assert seen["qcx_path"] == str(exe)
        assert seen["payload"]["meta"]["mode"] == "single"
        assert seen["ran"] is True

    def test_a_frozen_build_with_no_embedded_payload_starts_empty(self, monkeypatch,
                                                                  tmp_path):
        dec, seen = self._stub(monkeypatch)
        exe = tmp_path / "plain-binary"
        exe.write_bytes(b"\x7fELF not a qcx")
        monkeypatch.setattr(dec.sys, "frozen", True, raising=False)
        monkeypatch.setattr(dec.sys, "executable", str(exe))
        dec.main()
        assert seen["payload"] is None and seen["qcx_path"] is None
