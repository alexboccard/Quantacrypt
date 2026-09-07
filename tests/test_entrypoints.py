"""Behavioural tests for QuantaCrypt's three entry points.

``__main__.py`` decides which screen a launch lands on, ``cli.py`` is the
``qc-core`` helper process the SwiftUI shell talks to, and ``__init__.py``
resolves the version both of them report.  All three run before anything
else in the app does, and until now nothing pinned their behaviour.

The UI classes these modules reach for are replaced by recorders: the
contract under test is *routing* (which screen opens, with which argument,
and what happens when it fails), not what the wizards then draw.
"""

import importlib
import importlib.metadata
import io
import json
import logging
import os
import signal
import struct
import sys
import threading
import time
try:                       # tomllib is 3.11+; the matrix includes 3.10
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
import types
import zlib
from types import SimpleNamespace

import pytest

from quantacrypt.core import crypto as cc
from quantacrypt.core import service as service_mod
from quantacrypt.core.errors import friendly_error
from quantacrypt.core.service import ServiceStop

import quantacrypt
import quantacrypt.cli as qcli
import quantacrypt.__main__ as qmain

from tests.conftest import HAS_TKINTER, requires_tkinter

PYPROJECT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "pyproject.toml")


# ── Harness ──────────────────────────────────────────────────────────────────

class FakeRoot:
    """Stands in for the hidden Tk root and records what the entry point does
    to it, so a test can assert the launch actually reached a mainloop (or
    tore the root down instead of leaving an invisible app running)."""

    def __init__(self, createcommand_error=None):
        self.commands = {}
        self.after_calls = []
        self.mainloop_count = 0
        self.destroyed = False
        self.children = []
        self._createcommand_error = createcommand_error

    def winfo_children(self):
        return list(self.children)

    def createcommand(self, name, fn):
        if self._createcommand_error is not None:
            raise self._createcommand_error
        self.commands[name] = fn

    def after(self, ms, fn):
        self.after_calls.append((ms, fn))

    def mainloop(self):
        self.mainloop_count += 1

    def destroy(self):
        self.destroyed = True


@pytest.fixture
def ui(monkeypatch):
    """Replace the four UI modules ``__main__`` imports lazily with recorders.

    They are installed in ``sys.modules`` rather than patched onto the real
    modules because the entry point imports them *inside* the branch it
    takes — which is exactly the behaviour under test.
    """
    rec = SimpleNamespace(
        launchers=[], decryptors=[], volume_apps=[], load_pkg_calls=[], errors=[],
        volumes_opened=[],
        pkg={"meta": {"mode": "single"}, "original_name": "secret.txt"},
        load_pkg_error=None, volumes_error=None, deiconify_error=None,
        volume_app_error=None, decryptor_error=None, volume_app_hook=None,
    )

    launcher_mod = types.ModuleType("quantacrypt.ui.launcher")

    class LauncherApp:
        def __init__(self, root):
            self.root = root
            self.deiconify_calls = 0
            rec.launchers.append(self)

        def _open_volumes(self, volume_path=None):
            rec.volumes_opened.append(volume_path)
            if rec.volumes_error is not None:
                raise rec.volumes_error

        def deiconify(self):
            self.deiconify_calls += 1
            if rec.deiconify_error is not None:
                raise rec.deiconify_error

    launcher_mod.LauncherApp = LauncherApp
    monkeypatch.setitem(sys.modules, "quantacrypt.ui.launcher", launcher_mod)

    dec_mod = types.ModuleType("quantacrypt.ui.decryptor")

    def load_pkg(path):
        rec.load_pkg_calls.append(path)
        if rec.load_pkg_error is not None:
            raise rec.load_pkg_error
        return rec.pkg

    class DecryptorApp:
        def __init__(self, root, payload=None, qcx_path=None, on_close=None):
            rec.decryptors.append(SimpleNamespace(root=root, payload=payload,
                                                  qcx_path=qcx_path, on_close=on_close))
            if rec.decryptor_error is not None:
                raise rec.decryptor_error

    dec_mod.load_pkg = load_pkg
    dec_mod.DecryptorApp = DecryptorApp
    monkeypatch.setitem(sys.modules, "quantacrypt.ui.decryptor", dec_mod)

    vm_mod = types.ModuleType("quantacrypt.ui.volume_manager")

    class VolumeManagerApp:
        def __init__(self, root, volume_path=None):
            if rec.volume_app_hook is not None:
                rec.volume_app_hook()
            rec.volume_apps.append(SimpleNamespace(root=root, volume_path=volume_path))
            if rec.volume_app_error is not None:
                raise rec.volume_app_error

    vm_mod.VolumeManagerApp = VolumeManagerApp
    monkeypatch.setitem(sys.modules, "quantacrypt.ui.volume_manager", vm_mod)

    # ui.shared re-exports core.errors.friendly_error; use the real one so the
    # dialog text asserted below is the text a user would actually read.
    shared_mod = types.ModuleType("quantacrypt.ui.shared")
    shared_mod.friendly_error = friendly_error
    monkeypatch.setitem(sys.modules, "quantacrypt.ui.shared", shared_mod)

    mb = types.ModuleType("tkinter.messagebox")

    def showerror(title, message, parent=None, **kw):
        rec.errors.append(SimpleNamespace(title=title, message=message, parent=parent))

    mb.showerror = showerror
    monkeypatch.setitem(sys.modules, "tkinter.messagebox", mb)
    import tkinter
    monkeypatch.setattr(tkinter, "messagebox", mb, raising=False)

    return rec


@pytest.fixture
def app(monkeypatch, ui):
    """``main()`` wired to a recording root and an empty argv."""
    root = FakeRoot()
    monkeypatch.setattr(qmain, "_make_root", lambda: root)
    monkeypatch.setattr(sys, "argv", ["quantacrypt"])
    return root


def _payload_binary(tmp_path, name="app.bin"):
    """A file that passes the cheap self-executing-.qcx probe."""
    p = tmp_path / name
    p.write_bytes(b"\x00" * 4096 + qmain._QCX_MAGIC + b"\x00\x00\x00\x02{}")
    return str(p)


def _png_bytes(width, height):
    """A minimal valid 8-bit RGB PNG of the requested size.

    The icon tests need a file Tk will really decode *and* that is
    distinguishable from the shipped 512x512 icon — otherwise a test that
    loads the wrong icon.png passes anyway.
    """
    def chunk(tag, data):
        payload = tag + data
        return (len(data).to_bytes(4, "big") + payload
                + zlib.crc32(payload).to_bytes(4, "big"))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + b"\xff\x00\x00" * width for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


# ── _binary_has_qcx_payload ──────────────────────────────────────────────────

class TestBinaryHasQcxPayload:
    """The magic-bytes probe that decides whether to pay for importing the
    crypto stack at startup: it must never raise, and must only say yes when
    the marker really is inside the trailing 1 MB window."""

    def test_inlined_magic_still_matches_the_real_format(self):
        """The constant is duplicated to keep argon2/kyber off the startup
        path; if core.crypto's MAGIC ever moves, every self-executing binary
        silently stops being recognised."""
        assert qmain._QCX_MAGIC == cc.MAGIC

    def test_detects_a_payload_at_the_end_of_a_binary(self, tmp_path):
        assert qmain._binary_has_qcx_payload(_payload_binary(tmp_path)) is True

    def test_rejects_a_plain_binary(self, tmp_path):
        p = tmp_path / "plain.bin"
        p.write_bytes(b"not encrypted at all" * 100)
        assert qmain._binary_has_qcx_payload(str(p)) is False

    def test_a_file_that_is_only_the_magic_counts(self, tmp_path):
        p = tmp_path / "bare"
        p.write_bytes(qmain._QCX_MAGIC)
        assert qmain._binary_has_qcx_payload(str(p)) is True

    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty"
        p.write_bytes(b"")
        assert qmain._binary_has_qcx_payload(str(p)) is False

    def test_file_shorter_than_the_magic(self, tmp_path):
        p = tmp_path / "tiny"
        p.write_bytes(qmain._QCX_MAGIC[:3])
        assert qmain._binary_has_qcx_payload(str(p)) is False

    @pytest.mark.parametrize("offset_from_window_start, expected", [(0, True), (-1, False)])
    def test_the_tail_window_boundary(self, tmp_path, offset_from_window_start, expected):
        """The probe only reads the last _QCX_TAIL_SCAN bytes.  A marker that
        starts one byte earlier is straddling the window and must not match on
        its visible tail alone."""
        window = qmain._QCX_TAIL_SCAN
        size = window + 64
        at = (size - window) + offset_from_window_start
        buf = bytearray(b"\x00" * size)
        buf[at:at + len(qmain._QCX_MAGIC)] = qmain._QCX_MAGIC
        p = tmp_path / "big.bin"
        p.write_bytes(bytes(buf))
        assert qmain._binary_has_qcx_payload(str(p)) is expected

    def test_a_marker_further_back_than_the_window_is_invisible(self, tmp_path):
        """A binary's own data can contain the six magic bytes by chance; only
        an *appended* package lands in the trailing window, so a marker before
        it must not be mistaken for a payload."""
        size = qmain._QCX_TAIL_SCAN + 4096
        buf = bytearray(b"\x00" * size)
        buf[0:len(qmain._QCX_MAGIC)] = qmain._QCX_MAGIC
        p = tmp_path / "early.bin"
        p.write_bytes(bytes(buf))
        assert qmain._binary_has_qcx_payload(str(p)) is False

    def test_a_file_exactly_the_window_size_is_scanned_whole(self, tmp_path):
        """size == _QCX_TAIL_SCAN is the seek(0) boundary: tail is clamped to
        the file, so even a marker at offset 0 is inside the window."""
        buf = bytearray(b"\x00" * qmain._QCX_TAIL_SCAN)
        buf[0:len(qmain._QCX_MAGIC)] = qmain._QCX_MAGIC
        p = tmp_path / "exact.bin"
        p.write_bytes(bytes(buf))
        assert qmain._binary_has_qcx_payload(str(p)) is True

    def test_missing_path_is_not_a_payload(self, tmp_path):
        assert qmain._binary_has_qcx_payload(str(tmp_path / "nope")) is False

    def test_a_wrong_typed_path_still_raises(self):
        """Documented actual behaviour, not an endorsement: the guards are
        `except OSError`, so a non-path argument propagates a TypeError rather
        than being reported as "no payload".  Only reachable from a
        programming error — every real caller passes sys.executable or
        __file__ — so it is pinned here rather than filed as a bug."""
        with pytest.raises(TypeError):
            qmain._binary_has_qcx_payload(None)

    def test_directory_is_not_a_payload(self, tmp_path):
        """getsize() succeeds on a directory; the open() is what fails, so
        this exercises the second guard rather than the first."""
        d = tmp_path / "adir"
        d.mkdir()
        assert qmain._binary_has_qcx_payload(str(d)) is False

    @pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                        reason="root can read a 0o000 file")
    def test_unreadable_file_is_not_a_payload(self, tmp_path):
        p = tmp_path / "locked.bin"
        p.write_bytes(qmain._QCX_MAGIC)
        p.chmod(0o000)
        try:
            assert qmain._binary_has_qcx_payload(str(p)) is False
        finally:
            p.chmod(0o600)

    def test_path_with_spaces_and_quotes(self, tmp_path):
        p = tmp_path / 'a "quoted" nàme.bin'
        p.write_bytes(b"pad" + qmain._QCX_MAGIC)
        assert qmain._binary_has_qcx_payload(str(p)) is True


# ── _register_open_document ──────────────────────────────────────────────────

class TestRegisterQuit:
    """Run 18 F-205: Tk Aqua answers the Quit Apple event (app menu, Dock,
    ⌘Q) with `exit` unless ::tk::mac::Quit exists — no mounted-volume guard,
    no unmount, no clipboard wipe."""

    def test_the_launcher_is_asked_like_any_window_then_the_app_tears_down(self, monkeypatch):
        root = FakeRoot()
        launcher = SimpleNamespace(asked=0, winfo_exists=lambda: True)
        launcher.can_quit = lambda: (setattr(launcher, "asked", launcher.asked + 1), True)[1]
        wiped = []
        from quantacrypt.ui import shared
        monkeypatch.setattr(shared.ClipboardTimer, "wipe_all", classmethod(lambda cls: wiped.append(1)))
        qmain._register_quit(root, launcher)
        root.commands["::tk::mac::Quit"]()
        assert launcher.asked == 1 and root.destroyed and wiped == [1]

    def test_the_launcher_can_veto(self, monkeypatch):
        root = FakeRoot()
        launcher = SimpleNamespace(winfo_exists=lambda: True, can_quit=lambda: False)
        from quantacrypt.ui import shared
        monkeypatch.setattr(shared.ClipboardTimer, "wipe_all", classmethod(lambda cls: None))
        qmain._register_quit(root, launcher)
        root.commands["::tk::mac::Quit"]()
        assert not root.destroyed

    def test_wipes_the_clipboard_and_tears_down_without_a_launcher(self, monkeypatch):
        root = FakeRoot()
        wiped = []
        from quantacrypt.ui import shared
        monkeypatch.setattr(shared.ClipboardTimer, "wipe_all", classmethod(lambda cls: wiped.append(1)))
        qmain._register_quit(root)
        root.commands["::tk::mac::Quit"]()
        assert wiped == [1] and root.destroyed

    def test_a_gone_launcher_falls_back_to_the_teardown(self, monkeypatch):
        root = FakeRoot()
        gone = SimpleNamespace(winfo_exists=lambda: (_ for _ in ()).throw(RuntimeError("destroyed")),
                               can_quit=lambda: (_ for _ in ()).throw(RuntimeError("gone")))
        from quantacrypt.ui import shared
        monkeypatch.setattr(shared.ClipboardTimer, "wipe_all", classmethod(lambda cls: None))
        qmain._register_quit(root, gone)
        root.commands["::tk::mac::Quit"]()
        assert root.destroyed

    def test_survives_a_tk_without_the_command(self):
        root = FakeRoot(createcommand_error=RuntimeError("bad option"))
        qmain._register_quit(root)
        assert root.commands == {}

    def test_a_wizard_can_veto_the_quit_and_no_window_is_committed_first(self, monkeypatch):
        """Run 19 F-001 + run 20 F-005: every window's can_quit() is a pure
        predicate; a later veto must not leave an earlier window's job
        already cancelled, so commit_quit() runs only after all consent."""
        root = FakeRoot()
        events = []
        vetoer = SimpleNamespace(can_quit=lambda: events.append("veto-asked") or False)
        worker = SimpleNamespace(can_quit=lambda: events.append("worker-asked") or True,
                                 commit_quit=lambda: events.append("worker-committed"))
        root.children = [worker, vetoer]
        launcher = SimpleNamespace(winfo_exists=lambda: True, can_quit=lambda: True)
        from quantacrypt.ui import shared
        monkeypatch.setattr(shared.ClipboardTimer, "wipe_all", classmethod(lambda cls: None))
        qmain._register_quit(root, launcher)
        root.commands["::tk::mac::Quit"]()
        assert "worker-committed" not in events and not root.destroyed   # nothing committed on a veto
        vetoer.can_quit = lambda: True
        events.clear()
        root.commands["::tk::mac::Quit"]()
        assert "worker-committed" in events and root.destroyed

    def test_the_launcher_unmount_never_runs_before_a_wizard_vetoes(self, monkeypatch):
        """Run 21 F-002: the launcher's can_quit() unmounts as a side effect,
        so it must be asked LAST — a wizard that vetoes first must keep the
        drives mounted.  The prior tests only used a pure-lambda launcher."""
        root = FakeRoot()
        events = []
        # A launcher whose can_quit unmounts (the real one does), placed FIRST
        # in winfo_children() as the real LauncherApp is.
        launcher = SimpleNamespace(winfo_exists=lambda: True,
                                   can_quit=lambda: events.append("launcher-unmounted") or True)
        busy_wizard = SimpleNamespace(can_quit=lambda: events.append("wizard-vetoed") or False)
        root.children = [launcher, busy_wizard]
        from quantacrypt.ui import shared
        monkeypatch.setattr(shared.ClipboardTimer, "wipe_all", classmethod(lambda cls: None))
        qmain._register_quit(root, launcher)
        root.commands["::tk::mac::Quit"]()
        assert "launcher-unmounted" not in events, "the veto must precede the unmount"
        assert not root.destroyed
        # With the wizard consenting, the launcher is asked last and the app quits.
        busy_wizard.can_quit = lambda: events.append("wizard-ok") or True
        events.clear()
        root.commands["::tk::mac::Quit"]()
        assert events == ["wizard-ok", "launcher-unmounted"] and root.destroyed


class TestRegisterOpenDocument:
    """The macOS Apple Event handler: it routes dropped files to the right
    screen, keeps going when one of them is unopenable, and never lets an
    exception escape into the Tcl event loop (which would wedge it)."""

    def _handler(self, ui, createcommand_error=None):
        root = FakeRoot(createcommand_error=createcommand_error)
        qmain._register_open_document(root)
        return root

    def test_registers_the_command_and_survives_a_tk_that_has_none(self, ui, tmp_path):
        """Both halves in one test on purpose: "no command was registered" is
        also true of a handler that never registers anything, so the
        non-macOS case is only meaningful next to a root that *did* get the
        command and can still dispatch through it."""
        p = tmp_path / "vault.qcv"
        p.write_bytes(b"x")
        ok = self._handler(ui)
        hostile = self._handler(ui, createcommand_error=RuntimeError("bad option"))
        assert list(ok.commands) == ["::tk::mac::OpenDocument"]
        assert hostile.commands == {}, "a Tk without the command must be left alone"
        ok.commands["::tk::mac::OpenDocument"](str(p))
        assert [v.volume_path for v in ui.volume_apps] == [str(p)]

    def test_no_paths_opens_nothing(self, ui):
        root = self._handler(ui)
        root.commands["::tk::mac::OpenDocument"]()
        assert ui.volume_apps == [] and ui.decryptors == []

    def test_a_volume_opens_the_volume_manager(self, ui, tmp_path):
        p = tmp_path / "vault.qcv"
        p.write_bytes(b"x")
        root = self._handler(ui)
        root.commands["::tk::mac::OpenDocument"](str(p))
        assert [v.volume_path for v in ui.volume_apps] == [str(p)]
        assert ui.volume_apps[0].root is root
        assert ui.decryptors == [], "a .qcv must never reach the decryptor"

    def test_extension_match_is_case_insensitive(self, ui, tmp_path):
        p = tmp_path / "VAULT.QCV"
        p.write_bytes(b"x")
        root = self._handler(ui)
        root.commands["::tk::mac::OpenDocument"](str(p))
        assert [v.volume_path for v in ui.volume_apps] == [str(p)]

    def test_an_encrypted_file_opens_the_decryptor_with_its_payload(self, ui, tmp_path):
        p = tmp_path / "notes.qcx"
        p.write_bytes(b"x")
        root = self._handler(ui)
        root.commands["::tk::mac::OpenDocument"](str(p))
        assert ui.load_pkg_calls == [str(p)]
        assert len(ui.decryptors) == 1
        d = ui.decryptors[0]
        assert d.payload is ui.pkg and d.qcx_path == str(p)
        # on_close must be supplied here (unlike the argv path) so closing the
        # window does not leave the app running with nothing visible.
        assert callable(d.on_close) and d.on_close() is None

    def test_paths_that_are_not_files_are_skipped(self, ui, tmp_path):
        d = tmp_path / "folder.qcv"
        d.mkdir()
        root = self._handler(ui)
        root.commands["::tk::mac::OpenDocument"](str(tmp_path / "ghost.qcx"), str(d))
        assert ui.volume_apps == [] and ui.decryptors == [] and ui.load_pkg_calls == []

    def test_an_unreadable_package_does_not_stop_the_rest_of_the_drop(self, ui, tmp_path):
        bad = tmp_path / "corrupt.qcx"
        bad.write_bytes(b"x")
        good = tmp_path / "vault.qcv"
        good.write_bytes(b"x")
        ui.load_pkg_error = ValueError("Not a QuantaCrypt file")
        root = self._handler(ui)
        root.commands["::tk::mac::OpenDocument"](str(bad), str(good))
        assert ui.decryptors == []
        assert [v.volume_path for v in ui.volume_apps] == [str(good)]

    def test_an_oserror_reading_a_package_is_skipped_like_a_bad_one(self, ui, tmp_path):
        """The other half of the handler's `except (ValueError, OSError)`: the
        file was there when macOS built the event and is gone/unreadable by
        the time load_pkg opens it."""
        bad = tmp_path / "vanished.qcx"
        bad.write_bytes(b"x")
        good = tmp_path / "vault.qcv"
        good.write_bytes(b"x")
        ui.load_pkg_error = PermissionError(13, "Permission denied")
        root = self._handler(ui)
        root.commands["::tk::mac::OpenDocument"](str(bad), str(good))
        assert ui.decryptors == []
        assert [v.volume_path for v in ui.volume_apps] == [str(good)]

    def test_a_failing_volume_manager_does_not_stop_the_rest_of_the_drop(self, ui, tmp_path):
        bad = tmp_path / "a.qcv"
        bad.write_bytes(b"x")
        good = tmp_path / "b.qcx"
        good.write_bytes(b"x")
        ui.volume_app_error = RuntimeError("fusepy missing")
        root = self._handler(ui)
        root.commands["::tk::mac::OpenDocument"](str(bad), str(good))
        assert len(ui.volume_apps) == 1
        assert [d.qcx_path for d in ui.decryptors] == [str(good)]

    def test_a_failing_decryptor_window_is_swallowed(self, ui, tmp_path):
        a = tmp_path / "a.qcx"
        a.write_bytes(b"x")
        b = tmp_path / "b.qcx"
        b.write_bytes(b"x")
        ui.decryptor_error = RuntimeError("no display")
        root = self._handler(ui)
        root.commands["::tk::mac::OpenDocument"](str(a), str(b))
        # Both were attempted: one bad window must not abort the whole event.
        assert [d.qcx_path for d in ui.decryptors] == [str(a), str(b)]

    def test_many_mixed_paths_in_one_event(self, ui, tmp_path):
        names = ["one.qcv", "two.qcx", "three.QCV", "four.qcx"]
        for n in names:
            (tmp_path / n).write_bytes(b"x")
        root = self._handler(ui)
        root.commands["::tk::mac::OpenDocument"](*[str(tmp_path / n) for n in names])
        assert [os.path.basename(v.volume_path) for v in ui.volume_apps] == ["one.qcv", "three.QCV"]
        assert [os.path.basename(d.qcx_path) for d in ui.decryptors] == ["two.qcx", "four.qcx"]

    def test_concurrent_events_are_serialised(self, ui, tmp_path):
        """Two files dropped on the dock icon in quick succession arrive as two
        Apple Events; without the lock they build wizards for the same root at
        the same time."""
        live = {"now": 0, "max": 0}
        gate = threading.Lock()

        def hook():
            with gate:
                live["now"] += 1
                live["max"] = max(live["max"], live["now"])
            time.sleep(0.05)
            with gate:
                live["now"] -= 1

        ui.volume_app_hook = hook
        for n in ("a.qcv", "b.qcv"):
            (tmp_path / n).write_bytes(b"x")
        root = self._handler(ui)
        fn = root.commands["::tk::mac::OpenDocument"]
        threads = [threading.Thread(target=fn, args=(str(tmp_path / n),))
                   for n in ("a.qcv", "b.qcv")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        assert not any(t.is_alive() for t in threads)
        assert live["max"] == 1, "two Apple Events built wizards concurrently"
        assert len(ui.volume_apps) == 2

    def test_volume_import_failure_is_contained(self, ui, tmp_path, monkeypatch):
        """A broken lazy import (a hidden import missing from the bundle) is
        swallowed *and* the rest of the drop is still processed — "nothing
        happened" alone would also be true of a handler that gave up."""
        v = tmp_path / "v.qcv"
        v.write_bytes(b"x")
        later = tmp_path / "notes.qcx"
        later.write_bytes(b"x")
        monkeypatch.setitem(sys.modules, "quantacrypt.ui.volume_manager", None)
        root = self._handler(ui)
        root.commands["::tk::mac::OpenDocument"](str(v), str(later))
        assert ui.volume_apps == []
        assert [d.qcx_path for d in ui.decryptors] == [str(later)]

    def test_decryptor_import_failure_escapes_the_handler(self, ui, tmp_path, monkeypatch):
        """BUG (documented, not fixed): the .qcv branch guards its lazy import
        with `except Exception`, but the .qcx branch only catches
        (ValueError, OSError).  An ImportError there propagates straight into
        the Tcl event loop the handler was written to protect."""
        p = tmp_path / "f.qcx"
        p.write_bytes(b"x")
        later = tmp_path / "v.qcv"
        later.write_bytes(b"x")
        monkeypatch.setitem(sys.modules, "quantacrypt.ui.decryptor", None)
        root = self._handler(ui)
        with pytest.raises(ImportError):
            root.commands["::tk::mac::OpenDocument"](str(p), str(later))
        assert ui.volume_apps == [], "everything after the bad path is lost too"
        # The lock must still be released, or the next Apple Event deadlocks.
        assert qmain._open_document_lock.acquire(timeout=1)
        qmain._open_document_lock.release()

    def test_a_typeerror_from_load_pkg_escapes_the_handler(self, ui, tmp_path):
        """BUG (documented, not fixed): same narrow guard, reached without any
        import trouble.  core.package.load_pkg compares meta['version'] with
        `>` before type-checking it, so a corrupt envelope raises TypeError —
        outside `(ValueError, OSError)`.  Dropping such a file on the dock
        icon throws into the Tcl event loop and discards the rest of the
        drop, where every other corruption is silently skipped."""
        bad = tmp_path / "corrupt.qcx"
        bad.write_bytes(b"x")
        later = tmp_path / "vault.qcv"
        later.write_bytes(b"x")
        ui.load_pkg_error = TypeError("'>' not supported between 'str' and 'int'")
        root = self._handler(ui)
        with pytest.raises(TypeError):
            root.commands["::tk::mac::OpenDocument"](str(bad), str(later))
        assert ui.volume_apps == [] and ui.decryptors == []


# ── _make_root ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def display_problem():
    """conftest's tk_root skips when tkinter imports but no display is usable;
    the tests below build their own roots, so they need the same guard.
    Probed once per session — repeatedly creating and destroying Tk
    interpreters is exactly what _make_root's docstring warns about."""
    if not HAS_TKINTER:
        return "needs real tkinter"
    import tkinter as tk
    try:
        probe = tk.Tk()
    except tk.TclError as exc:
        return f"no usable display: {exc}"
    probe.destroy()
    return None


@requires_tkinter
class TestMakeRoot:
    """The single shared hidden root: never visible, and carrying the app
    icon so the dock does not show the stock Python rocket."""

    @pytest.fixture(autouse=True)
    def _needs_display(self, display_problem):
        if display_problem:
            pytest.skip(display_problem)

    def test_root_is_created_hidden_and_carries_the_source_icon(self):
        root = qmain._make_root()
        try:
            assert root.state() == "withdrawn"
            assert root.winfo_ismapped() == 0
            # src/quantacrypt/assets/icon.png ships as package data.
            assert root._icon_img.width() > 0 and root._icon_img.height() > 0
        finally:
            root.destroy()

    def test_drag_and_drop_root_is_preferred_when_available(self, monkeypatch):
        """tkinterdnd2's root is what makes the drop targets work; the plain
        Tk root is only the fallback."""
        import tkinter as tk
        made = []
        fake = types.ModuleType("tkinterdnd2")

        class TkinterDnD:
            @staticmethod
            def Tk():
                r = tk.Tk()
                made.append(r)
                return r

        fake.TkinterDnD = TkinterDnD
        monkeypatch.setitem(sys.modules, "tkinterdnd2", fake)
        root = qmain._make_root()
        try:
            assert made == [root]
            assert root.state() == "withdrawn"
        finally:
            root.destroy()

    def test_falls_back_to_plain_tk_without_tkinterdnd2(self, monkeypatch):
        import tkinter as tk
        monkeypatch.setitem(sys.modules, "tkinterdnd2", None)
        root = qmain._make_root()
        try:
            assert type(root) is tk.Tk
            assert root.state() == "withdrawn"
        finally:
            root.destroy()

    def test_frozen_bundle_loads_the_icon_from_the_unpack_dir(self, monkeypatch, tmp_path):
        """PyInstaller flattens assets/ into _MEIPASS, so the frozen path must
        look beside the binary, not in a source-tree subfolder.

        The _MEIPASS icon is deliberately a *different size* from the shipped
        one: copying the real icon there (the obvious way to write this test)
        makes both branches load an identical image, so deleting the frozen
        branch entirely would still pass.
        """
        import tkinter as tk
        (tmp_path / "icon.png").write_bytes(_png_bytes(7, 3))
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(qmain, "_base", str(tmp_path))
        root = qmain._make_root()
        try:
            src = os.path.join(os.path.dirname(os.path.abspath(qmain.__file__)),
                               "assets", "icon.png")
            shipped = tk.PhotoImage(file=src, master=root)
            assert (shipped.width(), shipped.height()) != (7, 3), \
                "fixture icon must be distinguishable from the source-tree one"
            assert (root._icon_img.width(), root._icon_img.height()) == (7, 3)
        finally:
            root.destroy()

    def test_a_corrupt_icon_does_not_stop_the_app_starting(self, monkeypatch, tmp_path):
        (tmp_path / "icon.png").write_bytes(b"this is not a PNG")
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(qmain, "_base", str(tmp_path))
        root = qmain._make_root()
        try:
            import tkinter as tk
            assert not hasattr(root, "_icon_img")
            assert root.state() == "withdrawn"
            # "does not stop the app starting" means the interpreter is still
            # live enough to build the Toplevels every screen is made of.
            top = tk.Toplevel(root)
            assert top.winfo_toplevel() is top
            top.destroy()
        finally:
            root.destroy()

    def test_a_missing_icon_does_not_stop_the_app_starting(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(qmain, "_base", str(tmp_path))   # empty dir
        root = qmain._make_root()
        try:
            assert not hasattr(root, "_icon_img")
            assert root.state() == "withdrawn"
        finally:
            root.destroy()


@requires_tkinter
class TestOpenDocumentThroughRealTcl:
    """The handler is dispatched by Tcl, not by Python.  Everything above
    reaches it through a recorded dict; this one goes through a real
    interpreter, so the command *name* and the string marshalling are covered
    too."""

    @pytest.fixture(autouse=True)
    def _needs_display(self, display_problem):
        if display_problem:
            pytest.skip(display_problem)

    def test_the_registered_command_is_dispatchable_from_the_interpreter(self, ui, tmp_path):
        import tkinter as tk
        p = tmp_path / 'dropped "nàme".qcx'
        p.write_bytes(b"x")
        root = tk.Tk()
        root.withdraw()
        try:
            qmain._register_open_document(root)
            root.tk.call("::tk::mac::OpenDocument", str(p))
        finally:
            root.destroy()
        assert [d.qcx_path for d in ui.decryptors] == [str(p)]
        assert ui.decryptors[0].payload is ui.pkg


# ── main(): launch routing ───────────────────────────────────────────────────

class TestLaunchRouting:
    """Which screen a launch lands on, given the binary, argv and the file on
    disk — and what the user is left with when the file cannot be opened."""

    def test_bare_launch_opens_the_launcher(self, app, ui):
        qmain.main()
        assert len(ui.launchers) == 1 and ui.launchers[0].root is app
        assert ui.decryptors == [] and ui.load_pkg_calls == []
        assert app.mainloop_count == 1

    def test_launch_registers_the_apple_event_handler(self, app, ui):
        qmain.main()
        assert "::tk::mac::OpenDocument" in app.commands

    def test_a_nonexistent_argument_falls_through_to_the_launcher(self, app, ui,
                                                                  monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "argv", ["quantacrypt", str(tmp_path / "gone.qcx")])
        qmain.main()
        assert len(ui.launchers) == 1 and ui.load_pkg_calls == []

    def test_a_directory_argument_falls_through_to_the_launcher(self, app, ui,
                                                                monkeypatch, tmp_path):
        monkeypatch.setattr(sys, "argv", ["quantacrypt", str(tmp_path)])
        qmain.main()
        assert len(ui.launchers) == 1 and ui.volume_apps == []

    def test_an_empty_path_argument_falls_through_to_the_launcher(self, app, ui,
                                                                  monkeypatch):
        """`open -a QuantaCrypt --args ""` and a few Finder edge cases hand us
        an empty argv[1]; it must not be treated as a .qcx to parse."""
        monkeypatch.setattr(sys, "argv", ["quantacrypt", ""])
        qmain.main()
        assert len(ui.launchers) == 1
        assert ui.load_pkg_calls == [] and ui.errors == []
        assert app.mainloop_count == 1 and app.destroyed is False

    def test_a_qcx_argument_opens_the_decryptor(self, app, ui, monkeypatch, tmp_path):
        p = tmp_path / "notes.qcx"
        p.write_bytes(b"x")
        monkeypatch.setattr(sys, "argv", ["quantacrypt", str(p)])
        qmain.main()
        assert ui.load_pkg_calls == [str(p)]
        assert len(ui.decryptors) == 1
        assert ui.decryptors[0].payload is ui.pkg
        assert ui.decryptors[0].qcx_path == str(p)
        assert ui.launchers == [], "the launcher must not also open"
        assert app.mainloop_count == 1

    def test_only_the_first_argument_is_used(self, app, ui, monkeypatch, tmp_path):
        first = tmp_path / "first.qcx"
        second = tmp_path / "second.qcx"
        first.write_bytes(b"x")
        second.write_bytes(b"x")
        monkeypatch.setattr(sys, "argv", ["quantacrypt", str(first), str(second)])
        qmain.main()
        assert ui.load_pkg_calls == [str(first)]

    def test_an_unopenable_qcx_reports_and_tears_the_root_down(self, app, ui,
                                                               monkeypatch, tmp_path):
        """No window ever appears, so the root must not be left alive with the
        app running invisibly."""
        p = tmp_path / 'my "weird" naïve nøtes.qcx'
        p.write_bytes(b"x")
        ui.load_pkg_error = ValueError("File appears truncated")
        monkeypatch.setattr(sys, "argv", ["quantacrypt", str(p)])
        qmain.main()
        assert len(ui.errors) == 1
        err = ui.errors[0]
        assert err.title == "Cannot open file"
        assert os.path.basename(str(p)) in err.message
        assert friendly_error(ui.load_pkg_error) in err.message
        assert err.parent is app
        assert ui.decryptors == [], "no half-built decryptor window"
        assert app.destroyed is True
        assert app.mainloop_count == 0

    def test_an_oserror_from_load_pkg_is_reported_too(self, app, ui, monkeypatch, tmp_path):
        p = tmp_path / "locked.qcx"
        p.write_bytes(b"x")
        ui.load_pkg_error = PermissionError(13, "Permission denied")
        monkeypatch.setattr(sys, "argv", ["quantacrypt", str(p)])
        qmain.main()
        assert ui.errors[0].title == "Cannot open file"
        assert app.destroyed is True

    def test_a_qcv_argument_opens_the_launcher_then_defers_the_volume(self, app, ui,
                                                                      monkeypatch, tmp_path):
        p = tmp_path / "vault.qcv"
        p.write_bytes(b"x")
        monkeypatch.setattr(sys, "argv", ["quantacrypt", str(p)])
        qmain.main()
        assert len(ui.launchers) == 1
        assert ui.decryptors == [] and ui.load_pkg_calls == []
        assert app.mainloop_count == 1
        # The open is deferred so it happens with the event loop already
        # running; nothing has been opened yet at this point.
        assert ui.volumes_opened == []
        assert [ms for ms, _ in app.after_calls] == [100]
        app.after_calls[0][1]()
        assert ui.volumes_opened == [str(p)]
        assert ui.errors == []

    def test_uppercase_qcv_argument_still_routes_to_volumes(self, app, ui,
                                                            monkeypatch, tmp_path):
        p = tmp_path / "VAULT.QCV"
        p.write_bytes(b"x")
        monkeypatch.setattr(sys, "argv", ["quantacrypt", str(p)])
        qmain.main()
        app.after_calls[0][1]()
        assert ui.volumes_opened == [str(p)]

    def test_a_failing_volume_open_surfaces_a_dialog_on_a_visible_window(
            self, app, ui, monkeypatch, tmp_path):
        """The launcher starts withdrawn; if the deferred open blows up it has
        to be shown, or the error dialog has no visible parent."""
        p = tmp_path / "vault.qcv"
        p.write_bytes(b"x")
        ui.volumes_error = RuntimeError("No FUSE backend found (macFUSE or FUSE-T)")
        monkeypatch.setattr(sys, "argv", ["quantacrypt", str(p)])
        qmain.main()
        app.after_calls[0][1]()
        launcher = ui.launchers[0]
        assert launcher.deiconify_calls == 1
        assert len(ui.errors) == 1
        err = ui.errors[0]
        assert err.title == "Cannot open volume"
        assert "vault.qcv" in err.message
        assert friendly_error(ui.volumes_error) in err.message
        assert err.parent is launcher
        assert app.destroyed is False, "the launcher stays up so the user can retry"

    def test_the_dialog_still_appears_when_the_launcher_cannot_be_shown(
            self, app, ui, monkeypatch, tmp_path):
        p = tmp_path / "vault.qcv"
        p.write_bytes(b"x")
        ui.volumes_error = RuntimeError("boom")
        ui.deiconify_error = RuntimeError("window already destroyed")
        monkeypatch.setattr(sys, "argv", ["quantacrypt", str(p)])
        qmain.main()
        app.after_calls[0][1]()
        assert len(ui.errors) == 1 and ui.errors[0].title == "Cannot open volume"

    def test_a_self_executing_binary_opens_its_own_payload(self, app, ui,
                                                           monkeypatch, tmp_path):
        exe = _payload_binary(tmp_path)
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", exe)
        monkeypatch.setattr(sys, "argv", [exe])
        qmain.main()
        assert ui.load_pkg_calls == [exe]
        assert len(ui.decryptors) == 1
        assert ui.decryptors[0].qcx_path == exe
        assert ui.decryptors[0].payload is ui.pkg
        assert ui.decryptors[0].on_close is None, "self-executing has no on_close"
        assert ui.launchers == []
        assert app.mainloop_count == 1

    def test_a_self_payload_argument_wins_over_argv(self, app, ui, monkeypatch, tmp_path):
        """A self-executing binary opened by double-click still gets argv from
        macOS; its own payload takes precedence."""
        exe = _payload_binary(tmp_path)
        other = tmp_path / "other.qcx"
        other.write_bytes(b"x")
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", exe)
        monkeypatch.setattr(sys, "argv", [exe, str(other)])
        qmain.main()
        assert ui.load_pkg_calls == [exe]

    def test_an_unparsable_self_payload_falls_through_to_the_launcher(self, app, ui,
                                                                      monkeypatch, tmp_path):
        """The magic can appear by chance in a binary; a failed parse must not
        strand the user on a dead screen."""
        exe = _payload_binary(tmp_path)
        ui.load_pkg_error = ValueError("Not a QuantaCrypt file")
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", exe)
        monkeypatch.setattr(sys, "argv", [exe])
        qmain.main()
        assert ui.load_pkg_calls == [exe]
        assert ui.decryptors == []
        assert len(ui.launchers) == 1
        assert app.mainloop_count == 1

    def test_an_empty_self_payload_falls_through_to_the_launcher(self, app, ui,
                                                                 monkeypatch, tmp_path):
        exe = _payload_binary(tmp_path)
        ui.pkg = {}
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", exe)
        monkeypatch.setattr(sys, "argv", [exe])
        qmain.main()
        assert ui.decryptors == [] and len(ui.launchers) == 1

    def test_a_frozen_binary_without_a_payload_reaches_argv_routing(self, app, ui,
                                                                    monkeypatch, tmp_path):
        exe = tmp_path / "clean.bin"
        exe.write_bytes(b"\x00" * 2048)
        target = tmp_path / "notes.qcx"
        target.write_bytes(b"x")
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "executable", str(exe))
        monkeypatch.setattr(sys, "argv", [str(exe), str(target)])
        qmain.main()
        assert ui.load_pkg_calls == [str(target)]
        assert ui.decryptors[0].qcx_path == str(target)


class TestRealPackageParsingAtLaunch:
    """The argv path with the real parser wired in.  ``ui.decryptor`` only
    re-exports ``core.package.load_pkg``, so this is the code that really runs
    when someone double-clicks a .qcx — and it decides which failures reach
    the user as a dialog rather than as a crash."""

    @pytest.fixture(autouse=True)
    def _real_load_pkg(self, ui, monkeypatch):
        from quantacrypt.core.package import load_pkg as real_load_pkg

        def counting(path):
            ui.load_pkg_calls.append(path)
            return real_load_pkg(path)

        monkeypatch.setattr(sys.modules["quantacrypt.ui.decryptor"], "load_pkg", counting)

    @staticmethod
    def _envelope(path, meta):
        blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
        path.write_bytes(b"\x00" * 16 + cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
        return str(path)

    def test_a_real_envelope_reaches_the_decryptor(self, app, ui, monkeypatch, tmp_path):
        target = self._envelope(tmp_path / "real.qcx",
                                {"mode": "single", "version": cc.MAX_FORMAT_VERSION,
                                 "kem": cc.KEM_DEFAULT, "argon2": cc.argon2_params()})
        monkeypatch.setattr(sys, "argv", ["quantacrypt", target])
        qmain.main()
        assert len(ui.decryptors) == 1
        assert ui.decryptors[0].payload["meta"]["mode"] == "single"
        assert ui.errors == [] and app.destroyed is False

    def test_a_file_that_is_not_a_package_is_reported_not_crashed(self, app, ui,
                                                                  monkeypatch, tmp_path):
        p = tmp_path / "holiday.jpg"
        p.write_bytes(b"just an ordinary file")
        monkeypatch.setattr(sys, "argv", ["quantacrypt", str(p)])
        qmain.main()
        assert [e.title for e in ui.errors] == ["Cannot open file"]
        assert "Not a QuantaCrypt file" in ui.errors[0].message
        assert ui.decryptors == [] and app.destroyed is True

    def test_a_future_format_version_is_reported_not_crashed(self, app, ui,
                                                             monkeypatch, tmp_path):
        target = self._envelope(tmp_path / "future.qcx",
                                {"mode": "single", "version": cc.MAX_FORMAT_VERSION + 1})
        monkeypatch.setattr(sys, "argv", ["quantacrypt", target])
        qmain.main()
        assert [e.title for e in ui.errors] == ["Cannot open file"]
        assert "newer version" in ui.errors[0].message
        assert app.destroyed is True

    def test_a_non_integer_format_version_is_reported_not_crashed(self, app, ui,
                                                                  monkeypatch, tmp_path):
        """load_pkg used to compare meta['version'] with `>` before checking
        its type, so a corrupt envelope carrying a string raised TypeError
        past main()'s handler and the launch died with a traceback.  Every
        ill-typed field is a format error now, and main() reports anything
        the parser raises."""
        target = self._envelope(tmp_path / "corrupt.qcx",
                                {"mode": "single", "version": "2"})
        monkeypatch.setattr(sys, "argv", ["quantacrypt", target])
        qmain.main()
        assert [e.title for e in ui.errors] == ["Cannot open file"]
        assert "not a number" in ui.errors[0].message
        assert app.destroyed is True


class TestFrozenModuleSetup:
    """PyInstaller unpacks bundled packages into _MEIPASS; import of the entry
    module has to make that directory importable or nothing else loads."""

    def test_meipass_is_prepended_to_sys_path_when_frozen(self, monkeypatch, tmp_path):
        original_path = list(sys.path)
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
        try:
            importlib.reload(qmain)
            assert qmain._base == str(tmp_path)
            assert sys.path[0] == str(tmp_path)
        finally:
            monkeypatch.undo()
            importlib.reload(qmain)
            sys.path[:] = original_path
        assert qmain._base == os.path.dirname(os.path.abspath(qmain.__file__))


# ── quantacrypt/__init__.py ──────────────────────────────────────────────────

class TestPackageVersion:
    """__version__ is what the `version` protocol op reports and what the
    updater compares against GitHub releases, so both of its sources matter."""

    @staticmethod
    def _pyproject_version():
        with open(PYPROJECT, "rb") as f:
            return tomllib.load(f)["project"]["version"]

    def test_installed_distribution_metadata_wins(self, monkeypatch):
        monkeypatch.setattr(importlib.metadata, "version", lambda name: "9.9.9-from-metadata")
        try:
            importlib.reload(quantacrypt)
            assert quantacrypt.__version__ == "9.9.9-from-metadata"
        finally:
            monkeypatch.undo()
            importlib.reload(quantacrypt)
        assert quantacrypt.__version__ == importlib.metadata.version("quantacrypt")

    def test_fallback_matches_pyproject_when_metadata_is_absent(self, monkeypatch):
        """Running from source or inside a PyInstaller bundle there is no
        installed distribution; the hardcoded fallback is then the only
        version the app reports, and it must not drift from pyproject.toml."""
        def _absent(name):
            raise importlib.metadata.PackageNotFoundError(name)

        monkeypatch.setattr(importlib.metadata, "version", _absent)
        try:
            importlib.reload(quantacrypt)
            assert quantacrypt.__version__ == self._pyproject_version()
        finally:
            monkeypatch.undo()
            importlib.reload(quantacrypt)

    def test_console_script_entry_point_returns_the_gui_exit_code(self, monkeypatch):
        """`quantacrypt` on the PATH is this function; its return value is the
        process exit status."""
        monkeypatch.setattr(qmain, "main", lambda: 7)
        assert quantacrypt.main() == 7


# ── qc-core CLI ──────────────────────────────────────────────────────────────

@pytest.fixture
def restore_signals():
    """cli.main() installs process-wide SIGTERM/SIGINT handlers."""
    saved = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
    yield
    for sig, handler in saved.items():
        signal.signal(sig, handler)


class TestHelperLogFormat:
    """Run 18 F-003: the Swift shell decides a stderr line's privacy by its
    level prefix, line by line; a traceback's frames arrived bare and were
    redacted — the cause line with them."""

    def test_every_traceback_line_carries_the_level_prefix(self):
        fmt = qcli._LevelPrefixedFormatter(qcli._LOG_FORMAT)
        try:
            raise PermissionError(13, "Permission denied", "/v/x.qcv")
        except PermissionError:
            rec = logging.LogRecord("quantacrypt.core.fuse_ops", logging.INFO, __file__, 1,
                                    "post-eject save failure at %s", ("/mnt/v",), sys.exc_info())
        lines = fmt.format(rec).split("\n")
        assert lines[0] == "qc-core INFO quantacrypt.core.fuse_ops: post-eject save failure at /mnt/v"
        assert len(lines) > 3
        assert all(l.startswith("qc-core INFO quantacrypt.core.fuse_ops: ") for l in lines[1:])
        assert lines[1].endswith("Traceback (most recent call last):")
        assert lines[-1].endswith("PermissionError: [Errno 13] Permission denied: '/v/x.qcv'")
        plain = logging.LogRecord("x", logging.ERROR, __file__, 1, "one line", (), None)
        assert fmt.format(plain) == "qc-core ERROR x: one line"

    def test_main_installs_it_on_the_root_logger(self, helper):
        logging.root.handlers[:] = []          # basicConfig is a no-op otherwise
        helper.run(io.StringIO(""))
        assert [type(h.formatter) for h in logging.root.handlers] == [qcli._LevelPrefixedFormatter]


@pytest.fixture
def root_log_handlers():
    """cli.main() calls logging.basicConfig; keep it out of later tests."""
    saved = logging.root.handlers[:]
    saved_level = logging.root.level
    yield
    logging.root.handlers[:] = saved
    logging.root.setLevel(saved_level)


@pytest.fixture
def helper(monkeypatch, restore_signals, root_log_handlers):
    """Run cli.main() in-process against fake stdio, capturing the Service."""
    created = []
    real_service = service_mod.Service

    class Recording(real_service):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            created.append(self)

    monkeypatch.setattr(service_mod, "Service", Recording)

    # latin-1 / unbuffered on purpose: main() must reconfigure it, because the
    # SwiftUI client reads one UTF-8 JSON object per line.
    out = io.TextIOWrapper(io.BytesIO(), encoding="latin-1", line_buffering=False,
                           write_through=False)

    def run(stdin, argv=None):
        monkeypatch.setattr(sys, "stdin", stdin)
        monkeypatch.setattr(sys, "stdout", out)
        return qcli.main([] if argv is None else argv)

    return SimpleNamespace(run=run, out=out, services=created,
                           events=lambda: [json.loads(l) for l
                                           in out.buffer.getvalue().decode("utf-8").splitlines()
                                           if l.strip()])


def _lines(*reqs):
    return io.StringIO("".join(json.dumps(r) + "\n" for r in reqs))


class TestQcCoreTermHandler:
    """SIGTERM while the loop is blocked on stdin: the handler raises
    ServiceStop once to unwind the read, main() swallows it and exits 0.
    (The joins inside shutdown() now catch a ServiceStop of their own, so
    this is the path that still has to reach main's except.)"""

    def test_a_signal_during_the_stdin_read_ends_the_session_cleanly(self, helper):
        class Interrupting(io.StringIO):
            def _fire(self):
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

            def __iter__(self):
                self._fire()
                return iter(())

            def readline(self, *a):
                self._fire()
                return ""

        assert helper.run(Interrupting()) == 0
        assert helper.services[-1]._shutdown_started


class TestQcCoreVersionFlag:
    """`qc-core --version` is what the build and the Swift shell use to check
    the bundled helper matches the app."""

    def test_prints_the_package_version_and_exits_zero(self, capsys, monkeypatch):
        class Explosive:
            def __iter__(self):
                raise AssertionError("--version must not start a session")

        monkeypatch.setattr(sys, "stdin", Explosive())
        assert qcli.main(["--version"]) == 0
        assert capsys.readouterr().out.strip() == quantacrypt.__version__

    def test_an_unknown_flag_is_a_usage_error(self, capsys):
        with pytest.raises(SystemExit) as exc:
            qcli.main(["--bogus"])
        assert exc.value.code == 2
        captured = capsys.readouterr()
        assert captured.out == "", "usage errors must not pollute the protocol stream"
        assert "--bogus" in captured.err


class TestQcCoreSession:
    """The stdin/stdout session: one JSON request per line in, one event per
    line out, until EOF or shutdown."""

    def test_serves_requests_until_eof(self, helper):
        rc = helper.run(_lines({"id": "1", "op": "ping"},
                               {"id": "2", "op": "version"}))
        assert rc == 0
        events = helper.events()
        assert [e["id"] for e in events] == ["1", "2"]
        assert all(e["event"] == "done" for e in events)
        assert events[1]["result"]["version"] == quantacrypt.__version__
        assert events[1]["result"]["format_version"] == cc.MAX_FORMAT_VERSION

    def test_stdout_is_reconfigured_to_line_buffered_utf8(self, helper):
        """The client blocks on readLine; a block-buffered stdout deadlocks it,
        and a locale-dependent encoding corrupts non-ASCII filenames."""
        assert helper.out.encoding == "latin-1" and helper.out.line_buffering is False
        helper.run(_lines({"id": "1", "op": "ping"}))
        assert helper.out.encoding == "utf-8"
        assert helper.out.line_buffering is True

    def test_stdin_is_reconfigured_to_strict_utf8(self, helper, monkeypatch):
        """The frozen helper's bootloader starts Python in isolated mode and
        never reads PYTHONIOENCODING, so stdin followed the C locale and a
        non-ASCII password arrived surrogate-escaped (review F-041)."""
        raw = io.BytesIO(json.dumps({"id": "1", "op": "ping"}).encode() + b"\n")
        stdin = io.TextIOWrapper(raw, encoding="latin-1", errors="surrogateescape")
        assert helper.run(stdin) == 0
        assert stdin.encoding == "utf-8" and stdin.errors == "strict"
        assert [e["id"] for e in helper.events()] == ["1"]

    def test_non_ascii_request_ids_survive_the_round_trip(self, helper):
        rid = "vøl—ümé-→-测试"
        helper.run(_lines({"id": rid, "op": "ping"}))
        assert [e["id"] for e in helper.events()] == [rid]

    def test_empty_stdin_serves_nothing_and_exits_zero(self, helper):
        """A client that connects and closes immediately.  Asserting only
        `rc == 0` and "no output" would also hold for a helper that never
        started a session at all, so pin that it did: a Service was built on
        the stdio it was handed, and stdout was set up for the protocol."""
        stdin = io.StringIO("")
        assert helper.run(stdin) == 0
        assert helper.events() == []
        assert len(helper.services) == 1
        svc = helper.services[0]
        assert svc._in is stdin and svc._out is helper.out
        assert helper.out.encoding == "utf-8" and helper.out.line_buffering is True

    def test_a_malformed_line_is_reported_and_the_session_continues(self, helper):
        stdin = io.StringIO("not json at all\n"
                            + json.dumps({"id": "after", "op": "ping"}) + "\n")
        assert helper.run(stdin) == 0
        events = helper.events()
        assert events[0]["event"] == "error" and events[0]["code"] == "invalid_request"
        assert [e["id"] for e in events[1:]] == ["after"]

    def test_the_shutdown_op_ends_the_session(self, helper):
        rc = helper.run(_lines({"id": "s", "op": "shutdown"},
                               {"id": "never", "op": "ping"}))
        assert rc == 0
        events = helper.events()
        assert events[-1] == {"id": "s", "event": "done", "result": {"unmount_failed": []}}
        assert [e["id"] for e in events] == ["s"], "requests after shutdown must not run"


class TestQcCoreSignals:
    """SIGTERM is how the SwiftUI shell stops the helper.  It has to unwind the
    blocked stdin read, tear down mounts, and exit 0 — never die with a
    traceback, which the client would read as a crash."""

    def test_sigterm_unwinds_the_read_and_exits_cleanly(self, helper):
        class SignallingStdin:
            """Delivers a real SIGTERM from inside the read, the way the OS
            interrupts the helper's blocked readline."""

            def __init__(self, lines):
                self._lines = list(lines)

            def __iter__(self):
                return self

            def __next__(self):
                if self._lines:
                    return self._lines.pop(0)
                signal.raise_signal(signal.SIGTERM)
                raise AssertionError("SIGTERM did not unwind the stdin read")

        rc = helper.run(SignallingStdin([json.dumps({"id": "p", "op": "ping"}) + "\n"]))
        assert rc == 0
        assert [e["id"] for e in helper.events()] == ["p"]
        # The client escalates with a second SIGTERM; it must not raise again
        # into a teardown that is already running.
        signal.raise_signal(signal.SIGTERM)

    def test_the_handler_cancels_in_flight_work_once(self, helper):
        helper.run(io.StringIO(""))
        handler = signal.getsignal(signal.SIGTERM)
        assert handler is signal.getsignal(signal.SIGINT), "Ctrl-C stops it the same way"
        svc = helper.services[0]
        req = service_mod._Request("busy", "encrypt", {})
        svc._reqs["busy"] = req
        assert not req.cancelled.is_set()
        with pytest.raises(ServiceStop):
            handler(signal.SIGTERM, None)
        assert req.cancelled.is_set(), "in-flight work must be told to stop"
        # Second signal: still cancels, but must not raise through teardown.
        req.cancelled.clear()
        assert handler(signal.SIGTERM, None) is None
        assert req.cancelled.is_set()

    def test_a_signal_during_teardown_still_exits_zero(self, helper, monkeypatch):
        """Real case: EOF ends the loop, then SIGTERM lands while run()'s
        finally is unmounting.  ServiceStop escapes run() past its own guard,
        and only cli.main()'s except keeps the exit status at 0."""
        from quantacrypt.core import fuse_ops

        def signal_during_unmount():
            signal.raise_signal(signal.SIGTERM)
            return []

        monkeypatch.setattr(fuse_ops, "get_mounted_volumes", signal_during_unmount)
        rc = helper.run(_lines({"id": "p", "op": "ping"}))
        assert rc == 0
        assert [e["id"] for e in helper.events()] == ["p"]
