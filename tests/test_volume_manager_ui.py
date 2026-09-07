"""Behavioural tests for the Volume Manager screen (``ui/volume_manager.py``).

These drive the real Toplevel: real widgets, real worker threads, real .qcv
files on disk.  Only what would leave the machine, block the run or need a
kernel extension is replaced — the themed modal dialogs, the file pickers,
desktop notifications and the FUSE mount itself.  The mount stand-in still
opens a real ``VolumeContainer`` with the key the screen derived, so a wrong
password fails for the real reason and the mounted-list statistics are the
container's own.

The window is kept mapped (parked off-screen via ``center_at``) rather than
withdrawn: Tk drops ``event_generate`` key events and stops tracking focus on
a non-viewable toplevel, and several tests below assert where the keyboard
landed after a validation failure.
"""

import os
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from quantacrypt.core import crypto as cc
from quantacrypt.core import volume as vol
from tests.conftest import _widget_texts, requires_tkinter

PW = "correct horse battery staple"


# ── Harness ──────────────────────────────────────────────────────────────────

def _pump_until(widget, predicate, timeout=20.0):
    """Run the Tk event loop until ``predicate`` holds.

    A real ``mainloop`` rather than repeated ``update()`` calls: tkinter
    refuses ``after()`` from a worker thread unless the main thread is inside
    the loop (``safe_after`` swallows that RuntimeError), and every result on
    this screen comes back from a worker.
    """
    deadline = time.monotonic() + timeout
    if predicate():
        widget.update()
        return True

    def _check():
        if predicate() or time.monotonic() > deadline or not widget.winfo_exists():
            widget.quit()
        else:
            widget.after(10, _check)

    widget.after(10, _check)
    widget.mainloop()
    try:
        widget.update()
    except Exception:
        pass
    return predicate()


def _flat_buttons(widget, out=None):
    from quantacrypt.ui.shared import FlatButton
    out = [] if out is None else out
    if isinstance(widget, FlatButton):
        out.append(widget)
    for child in widget.winfo_children():
        _flat_buttons(child, out)
    return out


def _button(widget, text):
    """The one FlatButton in ``widget``'s tree whose label is ``text``."""
    hits = [b for b in _flat_buttons(widget) if b.cget("text") == text]
    assert hits, f"no button {text!r} among {[b.cget('text') for b in _flat_buttons(widget)]}"
    return hits[0]


def _text_contents(widget, out=None):
    """The text held by every ``tk.Text`` in the tree — the share codes and
    the setup screen's command blocks are rendered there, not in labels."""
    import tkinter as tk
    out = [] if out is None else out
    if isinstance(widget, tk.Text):
        out.append(widget.get("1.0", "end").strip())
    for child in widget.winfo_children():
        _text_contents(child, out)
    return out


def _toplevel(app, title):
    for child in app.winfo_children():
        if child.winfo_class() == "Toplevel" and child.title() == title:
            return child
    return None


def _text_widgets(widget, out=None):
    import tkinter as tk
    out = [] if out is None else out
    if isinstance(widget, tk.Text):
        out.append(widget)
    for child in widget.winfo_children():
        _text_widgets(child, out)
    return out


def _shares_2_of_3():
    import secrets
    raw = cc.shamir_split(secrets.token_bytes(cc.KEY_BYTES), 3, 2)
    return [cc.encode_share(s) for s in raw]


class _Env:
    """Scripted stand-ins for everything the screen reaches outside itself."""

    OK_COMPONENTS = {"fusepy": {"ok": True, "detail": "fusepy is installed"},
                     "fuse_backend": {"ok": True, "detail": "macFUSE detected"}}
    MISSING_COMPONENTS = {"fusepy": {"ok": False, "detail": "fusepy is not installed"},
                          "fuse_backend": {"ok": False, "detail": "No FUSE backend found"}}

    def __init__(self, tk_root, tmp_path, vm, fo):
        self.tk_root, self.tmp_path, self.vm, self.fo = tk_root, tmp_path, vm, fo
        self.components = dict(self.OK_COMPONENTS)
        self.component_queue = []       # successive check_fuse_components() results
        self.mounted = {}
        self.mounted_error = None
        self.mount_error = None
        self.mount_suspicious = False
        self.unmount_error = None
        self.mount_calls, self.unmount_calls = [], []
        self.confirms, self.confirm_msgs = [], []
        self.alerts, self.notifications = [], []
        self._replies = []
        self.saveas = ""
        self.openfile = ""
        self.openfiles = ()
        self.directory = ""
        self.dialog_calls = []
        self.apps = []

    # -- dialogs ------------------------------------------------------------
    def reply(self, *values):
        """Queue answers for the next ``confirm()`` calls."""
        self._replies.extend(values)

    def confirm(self, parent, title, message, **kw):
        self.confirms.append(title)
        self.confirm_msgs.append(message)
        return self._replies.pop(0) if self._replies else False

    def alert(self, parent, title, message, **kw):
        self.alerts.append((title, message))

    def notify(self, title, message, sound=True):
        self.notifications.append((title, message))

    # -- fuse ---------------------------------------------------------------
    def check_components(self):
        if self.component_queue:
            self.components = self.component_queue.pop(0)
        return {k: dict(v) for k, v in self.components.items()}

    def get_mounted(self):
        if self.mounted_error is not None:
            raise self.mounted_error
        return dict(self.mounted)

    def mount(self, volume_path, final_key, mount_point, **kw):
        self.mount_calls.append((volume_path, mount_point))
        if self.mount_error is not None:
            raise self.mount_error
        os.makedirs(mount_point, exist_ok=True)
        vc = vol.VolumeContainer(volume_path, final_key)
        vc.open()                       # real: a wrong key fails authentication here
        if self.mount_suspicious:
            # Standing in for a rolled-back container; building one is a core
            # concern, the screen only reacts to the flag.
            vc.journal_suspicious = True
        self.mounted[mount_point] = {"volume_path": volume_path, "volume": vc}
        return SimpleNamespace(volume=vc)

    def unmount(self, mount_point):
        self.unmount_calls.append(mount_point)
        if self.unmount_error is not None:
            raise self.unmount_error
        self.mounted.pop(mount_point, None)

    # -- app ----------------------------------------------------------------
    #: Longer than the 50 ms ``after`` hop ``VolumeManagerApp.__init__``
    #: queues for ``_focus_first``.  Tk fires timers in expiry order, so a
    #: timer armed here with a longer delay is guaranteed to land after it.
    _OPEN_FOCUS_HOP_MS = 80

    def make(self, **kw):
        kw.setdefault("center_at", (-4000, -4000))
        app = self.vm.VolumeManagerApp(self.tk_root, **kw)
        self.apps.append(app)
        self.tk_root.update()
        self._settle_open_focus(app)
        return app

    @classmethod
    def _settle_open_focus(cls, app):
        """Let the window's opening keyboard hop land before the test runs.

        ``VolumeManagerApp.__init__`` ends with ``after(50, self._focus_first)``
        — the keyboard is put on the panel's first field a beat after the
        window appears.  A test that drives the window inside that 50 ms
        window (toggling a panel, or failing a mount) sets the focus itself,
        and *then* the opening hop fires and moves the keyboard back to the
        first field, so the focus assertion sees the wrong widget.  Whether it
        lands before or after depends purely on how long the preceding work
        took, which is exactly what a shuffled run varies.

        Draining it here makes the focus a test asserts on a consequence of
        what the test did, and nothing else.  This is deliberately not a
        ``sleep``: the loop has to run for the hop to fire at all.
        """
        landed = []
        try:
            app.after(cls._OPEN_FOCUS_HOP_MS, lambda: landed.append(True))
        except Exception:
            return
        _pump_until(app, lambda: bool(landed), 2)

    def close_all(self):
        for app in self.apps:
            try:
                if app.winfo_exists():
                    app._cancel_jobs()
                    app.destroy()
            except Exception:
                pass
        self.tk_root.update()


@pytest.fixture
def env(tk_root, tmp_path, monkeypatch):
    import quantacrypt.ui.volume_manager as vm
    from quantacrypt.core import fuse_ops as fo

    e = _Env(tk_root, tmp_path, vm, fo)
    monkeypatch.setattr(vm, "confirm", e.confirm)
    monkeypatch.setattr(vm, "alert", e.alert)
    monkeypatch.setattr(vm, "notify", e.notify)
    monkeypatch.setattr(vm.RecentVolumes, "_PATH", str(tmp_path / "recent-volumes.json"))
    monkeypatch.setattr(fo, "check_fuse_components", e.check_components)
    monkeypatch.setattr(fo, "get_mounted_volumes", e.get_mounted)
    monkeypatch.setattr(fo, "mount_volume", e.mount)
    monkeypatch.setattr(fo, "unmount_volume", e.unmount)
    monkeypatch.setattr(fo, "install_shutdown_handlers", lambda: None)

    def _saveas(**kw):
        e.dialog_calls.append(("asksaveasfilename", kw))
        return e.saveas

    def _openfile(**kw):
        e.dialog_calls.append(("askopenfilename", kw))
        return e.openfile

    def _openfiles(**kw):
        e.dialog_calls.append(("askopenfilenames", kw))
        return e.openfiles

    def _askdir(**kw):
        e.dialog_calls.append(("askdirectory", kw))
        return e.directory

    monkeypatch.setattr(vm.filedialog, "asksaveasfilename", _saveas)
    monkeypatch.setattr(vm.filedialog, "askopenfilename", _openfile)
    monkeypatch.setattr(vm.filedialog, "askopenfilenames", _openfiles)
    monkeypatch.setattr(vm.filedialog, "askdirectory", _askdir)
    try:
        yield e
    finally:
        e.close_all()


@pytest.fixture
def pw_volume(tmp_path):
    """A real password-protected .qcv."""
    path = str(tmp_path / "vault.qcv")
    vol.create_volume_single(path, PW)
    return path


# ── _find_stage ──────────────────────────────────────────────────────────────

@requires_tkinter
class TestFindStage:
    """Maps a core progress line onto the bar's stage index and label.  The
    two keyword tables differ because Shamir creation never derives a
    password key, so the same message must land on different stages."""

    def test_password_messages_map_to_their_stage(self):
        from quantacrypt.ui.volume_manager import _find_stage, STAGES_PASSWORD
        assert _find_stage("Deriving 512-bit password key (Argon2id)...") == \
            (0, "Securing password")
        assert _find_stage("Generating Kyber-768 keypair...") == (1, "Generating keys")
        assert _find_stage("Encapsulating + HKDF-SHA-512 expanding...") == \
            (1, "Generating keys")
        assert _find_stage("Writing volume container...") == (2, "Writing volume")
        assert _find_stage("Volume created.") == (2, "Writing volume")
        # STAGES is the back-compat alias, so passing it explicitly is the
        # same table as the default.
        assert _find_stage("argon2", STAGES_PASSWORD) == (0, "Securing password")

    def test_kyber_private_key_is_not_swallowed_by_the_kyber_match(self):
        """"Encrypting Kyber private key" contains both keywords; the more
        specific one is listed first and must win."""
        from quantacrypt.ui.volume_manager import _find_stage, STAGES_SHAMIR
        assert _find_stage("Encrypting Kyber private key...") == (2, "Writing volume")
        assert _find_stage("Encrypting Kyber private key...", STAGES_SHAMIR) == \
            (1, "Splitting key")

    def test_shamir_table_has_no_password_stage(self):
        from quantacrypt.ui.volume_manager import _find_stage, STAGES_SHAMIR
        assert _find_stage("Generating master key...", STAGES_SHAMIR) == \
            (0, "Generating keys")
        assert _find_stage("Generating Kyber-768 keypair...", STAGES_SHAMIR) == \
            (0, "Generating keys")
        assert _find_stage("Writing volume container...", STAGES_SHAMIR) == \
            (2, "Writing volume")
        # No stage in the Shamir list is called "Securing password".
        assert all("password" not in name.lower() for name, _ in STAGES_SHAMIR)

    def test_percentage_suffix_is_carried_into_the_label(self):
        from quantacrypt.ui.volume_manager import _find_stage
        assert _find_stage("Writing volume container... 45%") == \
            (2, "Writing volume 45%")
        assert _find_stage("Writing 100%") == (2, "Writing volume 100%")
        assert _find_stage("Writing 0%") == (2, "Writing volume 0%")

    def test_unknown_message_maps_to_nothing(self):
        from quantacrypt.ui.volume_manager import _find_stage
        assert _find_stage("") == (None, None)
        assert _find_stage("Doing something unheard of") == (None, None)

    def test_matching_is_case_insensitive(self):
        from quantacrypt.ui.volume_manager import _find_stage
        assert _find_stage("ARGON2 SOMETHING") == (0, "Securing password")


# ── _parse_share_text ────────────────────────────────────────────────────────

@requires_tkinter
class TestParseShareText:
    """Free text pasted into the mount panel → share entries.  Codes are
    re-encoded canonically, phrases are recovered, and a broken code is kept
    in place so normalize_shares can name it."""

    def test_empty_and_blank_input_yield_no_entries(self):
        from quantacrypt.ui.volume_manager import _parse_share_text
        assert _parse_share_text("") == []
        assert _parse_share_text("   \n\n\t  \n") == []
        # ``or ""`` guards a None from a caller that has no text widget yet.
        assert _parse_share_text(None) == []

    def test_a_single_code_survives_surrounding_whitespace(self):
        from quantacrypt.ui.volume_manager import _parse_share_text
        share = _shares_2_of_3()[0]
        assert _parse_share_text(f"   {share}   ") == [share]

    def test_a_case_folded_code_is_reported_rather_than_dropped(self):
        """The QCSHARE- prefix is matched case-insensitively but its payload
        is base64, so a lowercased code cannot decode.  It is kept verbatim
        so the user is told which line is broken instead of silently losing
        a share."""
        from quantacrypt.core import package as pkg
        from quantacrypt.ui.volume_manager import _parse_share_text
        share = _shares_2_of_3()[0]
        entries = _parse_share_text(share.lower())
        assert entries == [share.lower()]
        with pytest.raises(ValueError, match="Share 1"):
            pkg.normalize_shares(entries)

    def test_broken_code_is_kept_verbatim_for_naming(self):
        from quantacrypt.core import package as pkg
        from quantacrypt.ui.volume_manager import _parse_share_text
        good = _shares_2_of_3()[0]
        entries = _parse_share_text(f"QCSHARE-NOPE\n{good}")
        assert entries[0] == "QCSHARE-NOPE" and entries[1] == good
        with pytest.raises(ValueError, match="Share 1"):
            pkg.normalize_shares(entries)

    def test_a_phrase_already_present_as_a_code_is_not_added_twice(self):
        from quantacrypt.ui.volume_manager import _parse_share_text
        share = _shares_2_of_3()[0]
        mn = cc.share_to_mnemonic({**cc.decode_share(share), "threshold": 2})
        assert _parse_share_text(f"{share}\n{mn}") == [share]

    def test_a_phrase_on_its_own_is_recovered_as_a_code(self):
        from quantacrypt.ui.volume_manager import _parse_share_text
        share = _shares_2_of_3()[0]
        mn = cc.share_to_mnemonic({**cc.decode_share(share), "threshold": 2})
        assert _parse_share_text("my backup notes\n" + mn) == [share]

    def test_many_shares_keep_their_paste_order(self):
        from quantacrypt.ui.volume_manager import _parse_share_text
        shares = _shares_2_of_3()
        assert _parse_share_text("\n".join(reversed(shares))) == list(reversed(shares))


# ── _blames_mount_point ──────────────────────────────────────────────────────

@requires_tkinter
class TestBlamesMountPoint:
    """Decides whether a PermissionError is about the mount point (advice
    about folders) or about the .qcv (advice about the file)."""

    MP = "/Users/me/QuantaCrypt Volumes/vault"

    def test_the_mount_point_itself_and_its_parents_are_blamed(self):
        from quantacrypt.ui.volume_manager import _blames_mount_point
        assert _blames_mount_point(PermissionError(13, "denied", self.MP), self.MP)
        assert _blames_mount_point(
            PermissionError(13, "denied", "/Users/me/QuantaCrypt Volumes"), self.MP)
        assert _blames_mount_point(PermissionError(13, "denied", "/"), self.MP)

    def test_an_unrelated_file_is_not_blamed(self):
        from quantacrypt.ui.volume_manager import _blames_mount_point
        assert not _blames_mount_point(
            PermissionError(13, "denied", "/Users/me/vault.qcv"), self.MP)
        # …the same error against the mount point itself is blamed, so the
        # False above is a verdict and not a function that never says yes.
        assert _blames_mount_point(PermissionError(13, "denied", self.MP), self.MP)

    def test_a_sibling_sharing_a_name_prefix_is_not_a_parent(self):
        """Plain string prefixing would blame /Users/me/QuantaCrypt Vol — the
        separator is what makes a path a parent."""
        from quantacrypt.ui.volume_manager import _blames_mount_point
        assert not _blames_mount_point(
            PermissionError(13, "denied", "/Users/me/QuantaCrypt Vol"), self.MP)
        # One character further — the separator — and it really is a parent.
        assert _blames_mount_point(
            PermissionError(13, "denied", "/Users/me/QuantaCrypt Volumes"), self.MP)

    def test_a_missing_or_empty_filename_falls_back_to_the_mount_point(self):
        from quantacrypt.ui.volume_manager import _blames_mount_point
        assert _blames_mount_point(PermissionError(13, "denied"), self.MP)
        assert _blames_mount_point(PermissionError(13, "denied", ""), self.MP)

    def test_a_trailing_separator_does_not_change_the_verdict(self):
        from quantacrypt.ui.volume_manager import _blames_mount_point
        assert _blames_mount_point(
            PermissionError(13, "denied", "/Users/me/QuantaCrypt Volumes/"), self.MP)


# ── Window lifecycle ─────────────────────────────────────────────────────────

@requires_tkinter
class TestWindowLifecycle:
    """Opening, prefilling, switching panels and the four ways of closing."""

    def test_opens_on_the_create_panel_with_the_location_field_focused(self, env):
        app = env.make()
        assert app._mode_var.get() == "create"
        assert app._create_frame.winfo_ismapped()
        assert not app._mount_frame.winfo_ismapped()
        assert _pump_until(app, lambda: app.focus_lastfor() is app._loc_entry, 2)
        assert "Encrypted Volumes" in _widget_texts(app)

    def test_an_explicit_volume_path_opens_the_mount_panel_ready_to_go(
            self, env, pw_volume):
        app = env.make(volume_path=pw_volume)
        assert app._mode_var.get() == "mount"
        assert app._mount_frame.winfo_ismapped()
        assert app._mount_path_var.get() == pw_volume
        # The unlock mode and the mount point are read off the volume itself.
        assert app._mount_auth_var.get() == "password"
        assert app._vol_info_lbl.cget("text").startswith("Password-protected volume")
        assert app._mount_point_var.get().endswith(os.path.join(
            "QuantaCrypt Volumes", "vault"))

    def test_without_a_path_the_most_recent_volume_is_prefilled(self, env, pw_volume):
        env.vm.RecentVolumes.add(pw_volume, {"mode": "single"})
        app = env.make()
        assert app._mount_path_var.get() == pw_volume
        # …but the window still opens on Create, not Mount.
        assert app._mode_var.get() == "create"

    def test_an_empty_recents_list_leaves_the_path_blank(self, env, pw_volume):
        """Zero-recents case of the prefill.  The same window with one entry
        does fill the field, so the blank here is the empty list and not a
        prefill that never runs."""
        assert env.vm.RecentVolumes.load() == []
        app = env.make()
        assert app._mount_path_var.get() == ""
        assert app._vol_info_lbl.cget("text") == ""
        env.vm.RecentVolumes.add(pw_volume, {"mode": "single"})
        assert env.make()._mount_path_var.get() == pw_volume

    def test_switching_mode_swaps_the_visible_panel(self, env):
        app = env.make()
        app._mode_var.set("mount")
        app.update()
        assert app._mount_frame.winfo_ismapped() and not app._create_frame.winfo_ismapped()
        app._mode_var.set("create")
        app.update()
        assert app._create_frame.winfo_ismapped() and not app._mount_frame.winfo_ismapped()

    def test_focus_follows_the_panel_and_the_unlock_mode(self, env, pw_volume):
        app = env.make(volume_path=pw_volume)
        assert _pump_until(app, lambda: app.focus_lastfor() is app._mount_pw_entry, 2)
        app._mount_auth_var.set("shamir")
        app.update()
        app._focus_first()
        assert _pump_until(app, lambda: app.focus_lastfor() is app._mount_shares_text, 2)
        app._mode_var.set("create")
        app.update()
        assert _pump_until(app, lambda: app.focus_lastfor() is app._loc_entry, 2)

    def test_with_no_volume_chosen_the_keyboard_lands_on_the_path_field(self, env):
        app = env.make()
        app._mode_var.set("mount")
        app.update()
        assert _pump_until(app, lambda: app.focus_lastfor() is app._mount_path_entry, 2)

    def test_the_queued_focus_hop_survives_a_field_that_was_torn_down(self, env):
        """``__init__`` queues ``_focus_first`` on a 50 ms hop, so it can land
        after a close has destroyed the field it wants.  Returning quietly is
        the contract here — the blanket guard exists for exactly this race —
        and the window must be left otherwise untouched."""
        import tkinter as tk
        app = env.make()
        app._loc_entry.destroy()
        with pytest.raises(tk.TclError):
            app._loc_entry.focus_set()       # the bare call really does raise
        app._focus_first()                   # …and the guard absorbs it
        assert app.winfo_exists()
        assert app._mode_var.get() == "create"

    def test_a_clean_close_destroys_the_window_and_calls_back(self, env):
        closed = []
        app = env.make(on_close=lambda: closed.append(True))
        app._close()
        assert not app.winfo_exists()
        assert closed == [True]
        assert env.confirms == []          # nothing to lose → no question asked

    def test_close_with_no_callback_still_destroys(self, env):
        app = env.make()
        app._close()
        assert not app.winfo_exists()

    @pytest.mark.parametrize("field,value", [
        ("_pw_var", "typed"), ("_pw2_var", "typed"), ("_mount_pw_var", "typed"),
    ])
    def test_typed_credentials_are_confirmed_before_being_thrown_away(
            self, env, field, value):
        app = env.make()
        getattr(app, field).set(value)
        assert app._has_typed_input()
        env.reply(False)
        app._close()
        assert app.winfo_exists(), "Keep editing must leave the window open"
        assert env.confirms == ["Discard what you typed?"]
        env.reply(True)
        app._close()
        assert not app.winfo_exists()

    def test_pasted_shares_also_count_as_typed_input(self, env):
        app = env.make()
        app._mount_shares_text.insert("1.0", "QCSHARE-something\n")
        assert app._has_typed_input()
        env.reply(False)
        app._close()
        assert app.winfo_exists()
        assert env.confirms == ["Discard what you typed?"]

    def test_has_typed_input_tolerates_a_half_built_window(self):
        """The guard runs from ``_close``, which can fire before the mount
        panel exists; a missing field must read as 'nothing typed', not blow
        up the close."""
        from quantacrypt.ui.volume_manager import VolumeManagerApp
        assert VolumeManagerApp._has_typed_input(SimpleNamespace()) is False

    def test_unsaved_shares_are_confirmed_before_closing(self, env):
        app = env.make()
        app._pending_shares = ["QCSHARE-a", "QCSHARE-b"]
        env.reply(False)
        app._close()
        assert app.winfo_exists()
        assert env.confirms == ["Shares not saved"]
        env.reply(True)
        app._close()
        assert not app.winfo_exists()

    def test_closing_during_creation_asks_and_cancels_the_worker(self, env):
        app = env.make()
        app._busy, app._busy_what = True, "create"
        env.reply(False)
        app._close()
        assert app.winfo_exists() and not app._cancel_event.is_set()
        assert env.confirms == ["Creation is still running"]
        env.reply(True)
        app._close()
        assert not app.winfo_exists()
        assert app._cancel_event.is_set(), "closing must flag the create worker"

    def test_closing_during_a_mount_warns_that_it_cannot_be_interrupted(self, env):
        app = env.make()
        app._busy, app._busy_what = True, "mount"
        env.reply(False)
        app._close()
        assert app.winfo_exists()
        assert env.confirms == ["Mounting is still running"]
        env.reply(True)
        app._close()
        assert not app.winfo_exists()

    def test_closing_cancels_every_pending_timer(self, env):
        app = env.make()
        app._set_status("still here")
        app._start_ticker("fuse_backend", "Installing…")
        assert app._status_job is not None and app._refresh_job is not None
        app._close()
        assert app._status_job is None and app._refresh_job is None
        assert app._tickers == {}

    def test_cancel_jobs_is_idempotent(self, env):
        """It runs from ``_close`` and again from the fixture teardown; the
        second pass must not raise on already-cancelled ids."""
        app = env.make()
        app._cancel_jobs()
        app._cancel_jobs()
        assert app._refresh_job is None

    def test_center_at_positions_the_window_around_the_given_point(self, env):
        """The window manager clamps the final placement (macOS will not put a
        window at -4000), so the requested geometry is the observable here."""
        app = env.make()
        asked = []
        app.geometry = lambda spec: asked.append(spec)
        app._center_at = (500, 400)
        app._center()
        w, h = app.winfo_width(), app.winfo_height()
        assert asked == [f"+{500 - w // 2}+{400 - h // 2}"]

    def test_without_center_at_the_window_is_centred_on_the_screen(self, env):
        app = env.make()
        asked = []
        app.geometry = lambda spec: asked.append(spec)
        app._center_at = None
        app._center()
        w, h = app.winfo_width(), app.winfo_height()
        sw, sh = app.winfo_screenwidth(), app.winfo_screenheight()
        assert asked == [f"+{(sw - w) // 2}+{(sh - h) // 2}"]

    def test_show_and_hide_toggles_the_entry_mask_and_the_button(self, env):
        app = env.make()
        assert app._pw_entry.cget("show") == "•"
        app._toggle_show(app._pw_entry, app._pw_show)
        assert app._pw_entry.cget("show") == "" and app._pw_show.cget("text") == "Hide"
        app._toggle_show(app._pw_entry, app._pw_show)
        assert app._pw_entry.cget("show") == "•" and app._pw_show.cget("text") == "Show"

    def test_status_line_expires_on_its_own(self, env):
        app = env.make()
        app._STATUS_TTL_MS = 30
        app._set_status("Mounted at /tmp/x")
        assert app._mount_status.cget("text") == "Mounted at /tmp/x"
        assert _pump_until(app, lambda: app._mount_status.cget("text") == "", 3)

    def test_a_non_expiring_status_arms_no_timer_and_replaces_the_old_one(self, env):
        app = env.make()
        app._set_status("first")
        first_job = app._status_job
        app._set_status("second")
        assert app._status_job is not None and app._status_job != first_job
        app._set_status("", expire=False)
        assert app._status_job is None
        assert app._mount_status.cget("text") == ""

    @pytest.mark.needs_real_window
    def test_the_protection_toggle_swaps_password_and_split_key_fields(self, env):
        app = env.make()
        assert app._pw_frame.winfo_ismapped() and not app._shamir_frame.winfo_ismapped()
        app._auth_var.set("shamir")
        app.update()
        assert app._shamir_frame.winfo_ismapped() and not app._pw_frame.winfo_ismapped()
        assert _pump_until(app, lambda: app.focus_lastfor() is app._n_entry, 2)
        app._auth_var.set("password")
        app.update()
        assert app._pw_frame.winfo_ismapped() and not app._shamir_frame.winfo_ismapped()
        assert _pump_until(app, lambda: app.focus_lastfor() is app._pw_entry, 2)

    def test_the_unlock_toggle_swaps_password_and_shares_fields(self, env):
        app = env.make()
        app._mode_var.set("mount")
        app.update()
        assert app._mount_pw_frame.winfo_ismapped()
        app._mount_auth_var.set("shamir")
        app.update()
        assert app._mount_shares_frame.winfo_ismapped()
        assert not app._mount_pw_frame.winfo_ismapped()
        app._mount_auth_var.set("password")
        app.update()
        assert app._mount_pw_frame.winfo_ismapped()
        assert not app._mount_shares_frame.winfo_ismapped()

    def test_the_fuse_warning_strip_is_hidden_while_fuse_works(self, env):
        """The strip is always built — only its packing is conditional — so
        an unmapped-but-present widget is the right observation here."""
        app = env.make()
        assert app._fuse_ok
        assert app._fuse_warn.outer.winfo_exists()
        assert any("Mounting needs disk-mounting support" in t
                   for t in _widget_texts(app._fuse_warn))
        assert not app._fuse_warn.outer.winfo_ismapped()

    def test_browse_buttons_fill_their_fields_and_cancelling_leaves_them(self, env):
        app = env.make()
        env.saveas = str(env.tmp_path / "picked.qcv")
        app._browse_save_location()
        assert app._loc_var.get() == env.saveas
        env.saveas = ""
        app._browse_save_location()
        assert app._loc_var.get() == str(env.tmp_path / "picked.qcv")

        env.directory = "/tmp/some mount"
        app._browse_mount_point()
        assert app._mount_point_var.get() == "/tmp/some mount"
        env.directory = ""
        app._browse_mount_point()
        assert app._mount_point_var.get() == "/tmp/some mount"

    def test_browsing_for_a_volume_loads_it_and_moves_the_keyboard(
            self, env, pw_volume):
        app = env.make()
        app._mode_var.set("mount")
        app.update()
        env.openfile = pw_volume
        app._browse_volume()
        assert app._mount_path_var.get() == pw_volume
        assert app._vol_info_lbl.cget("text").startswith("Password-protected volume")
        # A pick moves the keyboard on to the credential it just discovered.
        assert _pump_until(app, lambda: app.focus_lastfor() is app._mount_pw_entry, 2)
        app._mount_path_entry.focus_set()
        app.update()
        env.openfile = ""
        app._browse_volume()
        assert app._mount_path_var.get() == pw_volume     # cancel changes nothing
        assert app.focus_lastfor() is app._mount_path_entry, \
            "a cancelled pick must not move the keyboard either"


# ── Create panel ─────────────────────────────────────────────────────────────

@pytest.fixture
def nomodal(monkeypatch):
    """Neutralise ``wait_window`` so a modal child window does not park the
    test inside a nested Tk event loop.  The window itself is still built and
    can be driven afterwards."""
    import tkinter as tk
    monkeypatch.setattr(tk.Misc, "wait_window", lambda self, window=None: None)


def _set_password(app, pw, confirm_pw=None):
    """Fill both password fields and let the strength worker settle, so the
    score ``_do_create`` reads is the one for this password."""
    app._pw_var.set(pw)
    app._pw2_var.set(pw if confirm_pw is None else confirm_pw)
    _pump_until(app, lambda: app._pw_strength.score_for(pw) is not None, 2)
    app.update()


@requires_tkinter
class TestCreateValidation:
    """Everything ``_do_create`` refuses before it touches the disk.  Each
    refusal must show a reason, move the keyboard to the offending field and
    leave no file behind."""

    def test_a_second_click_while_busy_is_ignored(self, env):
        app = env.make()
        app._err.config(text="previous message")
        app._loc_var.set(str(env.tmp_path / "x.qcv"))
        app._busy = True
        app._do_create()
        assert app._err.cget("text") == "previous message"
        assert not os.path.exists(env.tmp_path / "x.qcv")
        # The busy flag is what stopped it, not a form that was invalid
        # anyway: the identical click with the flag down gets as far as the
        # credential check.
        app._busy = False
        app._do_create()
        assert app._err.cget("text") == "Enter a password."
        assert not os.path.exists(env.tmp_path / "x.qcv")

    def test_an_empty_location_is_refused(self, env):
        app = env.make()
        app._loc_var.set("   ")
        app._do_create()
        assert app._err.cget("text") == "Choose where to save the volume."
        assert app.focus_lastfor() is app._loc_entry
        assert not app._busy

    def test_a_missing_password_is_refused(self, env):
        app = env.make()
        app._loc_var.set(str(env.tmp_path / "v.qcv"))
        app._do_create()
        assert app._err.cget("text") == "Enter a password."
        assert app.focus_lastfor() is app._pw_entry
        assert not os.path.exists(env.tmp_path / "v.qcv")

    def test_mismatched_passwords_are_refused(self, env):
        app = env.make()
        app._loc_var.set(str(env.tmp_path / "v.qcv"))
        _set_password(app, PW, confirm_pw=PW + "!")
        app._do_create()
        assert app._err.cget("text") == "The two passwords don't match."
        assert app.focus_lastfor() is app._pw2_entry
        assert not os.path.exists(env.tmp_path / "v.qcv")

    def test_a_weak_password_can_be_refused_at_the_prompt(self, env):
        app = env.make()
        path = env.tmp_path / "weak.qcv"
        app._loc_var.set(str(path))
        _set_password(app, "pwpwpwpwpw")          # zxcvbn scores this 1
        env.reply(False)
        app._do_create()
        assert env.confirms == ["Weak password"]
        assert not os.path.exists(path)
        assert app.focus_lastfor() is app._pw_entry
        assert not app._busy

    def test_a_weak_password_can_be_accepted_at_the_prompt(self, env):
        app = env.make()
        path = env.tmp_path / "weak.qcv"
        app._loc_var.set(str(path))
        _set_password(app, "pwpwpwpwpw")
        env.reply(True, False)                    # weak → use it; created → later
        app._do_create()
        assert _pump_until(app, lambda: not app._busy)
        assert env.confirms == ["Weak password", "Volume created"]
        # The weak password really does open the volume that was written.
        _hdr, auth = vol.read_volume_auth_params(str(path))
        assert vol.derive_volume_key_single("pwpwpwpwpw", auth)

    @pytest.mark.parametrize("n,k", [("", "2"), ("three", "2"), ("3", "two"),
                                     ("3.5", "2")])
    def test_non_integer_share_counts_are_refused(self, env, n, k):
        app = env.make()
        app._auth_var.set("shamir")
        app.update()
        app._loc_var.set(str(env.tmp_path / "s.qcv"))
        app._n_var.set(n)
        app._k_var.set(k)
        app._do_create()
        assert app._err.cget("text").startswith("Enter whole numbers")
        assert app.focus_lastfor() is app._n_entry
        assert not os.path.exists(env.tmp_path / "s.qcv")

    @pytest.mark.parametrize("n", ["1", "0", "-3", "21"])
    def test_share_totals_outside_2_to_20_are_refused(self, env, n):
        app = env.make()
        app._auth_var.set("shamir")
        app.update()
        app._loc_var.set(str(env.tmp_path / "s.qcv"))
        app._n_var.set(n)
        app._k_var.set("2")
        app._do_create()
        assert app._err.cget("text") == "Total shares must be between 2 and 20."
        assert app.focus_lastfor() is app._n_entry
        assert not os.path.exists(env.tmp_path / "s.qcv")

    @pytest.mark.parametrize("k", ["1", "0", "4"])
    def test_a_threshold_outside_2_to_n_is_refused(self, env, k):
        app = env.make()
        app._auth_var.set("shamir")
        app.update()
        app._loc_var.set(str(env.tmp_path / "s.qcv"))
        app._n_var.set("3")
        app._k_var.set(k)
        app._do_create()
        assert app._err.cget("text") == "Required shares must be between 2 and 3."
        assert app.focus_lastfor() is app._k_entry
        assert not os.path.exists(env.tmp_path / "s.qcv")

    @pytest.mark.parametrize("n,k", [(2, 2), (20, 2)])
    def test_the_accepted_bounds_really_produce_that_split(self, env, nomodal, n, k):
        app = env.make()
        app._auth_var.set("shamir")
        app.update()
        path = env.tmp_path / f"s{n}-{k}.qcv"
        app._loc_var.set(str(path))
        app._n_var.set(str(n))
        app._k_var.set(str(k))
        env.reply(False)                      # "Mount it now?" → Later
        app._do_create()
        assert _pump_until(app, lambda: not app._busy)
        assert app._err.cget("text") == f"✓ Created s{n}-{k}.qcv"
        shares = app._pending_shares
        assert len(shares) == n
        _hdr, auth = vol.read_volume_auth_params(str(path))
        assert (auth["threshold"], auth["total"]) == (k, n)
        # Any k of the n shares really do unlock it.
        key = vol.derive_volume_key_shamir(shares[-k:], auth)
        vol.VolumeContainer(str(path), key).open()


@requires_tkinter
class TestCreateOverwriteGuards:
    """Creating replaces the target atomically, so an existing or mounted
    volume at that path must be defended before a single byte is written."""

    def test_a_volume_mounted_in_this_process_is_never_overwritten(
            self, env, pw_volume):
        app = env.make()
        env.mounted["/tmp/mnt"] = {"volume_path": pw_volume}
        before = open(pw_volume, "rb").read()
        app._loc_var.set(pw_volume)
        _set_password(app, PW)
        app._do_create()
        assert [t for t, _ in env.alerts] == ["Volume is mounted"]
        assert "/tmp/mnt" in env.alerts[0][1]
        assert open(pw_volume, "rb").read() == before
        assert not app._busy

    def test_a_volume_locked_by_another_process_is_never_overwritten(
            self, env, pw_volume, monkeypatch):
        app = env.make()

        def _locked(path):
            raise RuntimeError("Volume appears to be mounted by another process")
        monkeypatch.setattr(env.fo, "_acquire_volume_lock", _locked)
        before = open(pw_volume, "rb").read()
        app._loc_var.set(pw_volume)
        _set_password(app, PW)
        app._do_create()
        assert [t for t, _ in env.alerts] == ["Volume is mounted"]
        assert "another" in env.alerts[0][1]
        assert open(pw_volume, "rb").read() == before

    def test_an_unavailable_lock_probe_falls_through_to_the_prompt(
            self, env, pw_volume, monkeypatch):
        """The probe is best-effort: an OSError from it must not block a
        legitimate overwrite, it just leaves the confirmation as the guard."""
        app = env.make()
        monkeypatch.setattr(env.fo, "_acquire_volume_lock",
                            lambda p: (_ for _ in ()).throw(OSError("no fcntl")))
        before = open(pw_volume, "rb").read()
        app._loc_var.set(pw_volume)
        _set_password(app, PW)
        env.reply(False)                       # Overwrite? → Cancel
        app._do_create()
        assert env.confirms == ["Overwrite volume?"]
        assert open(pw_volume, "rb").read() == before

    def test_declining_the_overwrite_leaves_the_existing_file_byte_identical(
            self, env, pw_volume):
        app = env.make()
        before = open(pw_volume, "rb").read()
        app._loc_var.set(pw_volume)
        _set_password(app, PW)
        env.reply(False)
        app._do_create()
        assert env.confirms == ["Overwrite volume?"]
        assert open(pw_volume, "rb").read() == before
        assert not app._busy

    def test_accepting_the_overwrite_replaces_the_volume(self, env, pw_volume):
        app = env.make()
        before = open(pw_volume, "rb").read()
        app._loc_var.set(pw_volume)
        _set_password(app, "another good passphrase")
        env.reply(True, False)                 # Overwrite → yes; mount now → later
        app._do_create()
        assert _pump_until(app, lambda: not app._busy)
        after = open(pw_volume, "rb").read()
        assert after != before
        _hdr, auth = vol.read_volume_auth_params(pw_volume)
        vol.VolumeContainer(
            pw_volume,
            vol.derive_volume_key_single("another good passphrase", auth)).open()
        # Replaced, not amended: the old password no longer derives a key
        # (the sk blob is AES-GCM, so a wrong Argon2 key fails to unwrap).
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            vol.derive_volume_key_single(PW, auth)

    def test_a_broken_mount_registry_does_not_block_creation(self, env):
        """fuse_ops may be unimportable or the registry unreadable; nothing
        can be mounted then, so creation must simply proceed."""
        app = env.make()
        env.mounted_error = RuntimeError("registry unavailable")
        path = env.tmp_path / "fresh.qcv"
        app._loc_var.set(str(path))
        _set_password(app, PW)
        env.reply(False)
        app._do_create()
        assert _pump_until(app, lambda: not app._busy)
        assert os.path.exists(path)
        assert env.alerts == []


@requires_tkinter
class TestCreateRun:
    """A creation that actually runs: what lands on disk, what the form says
    afterwards, and what a cancel leaves behind."""

    def test_a_password_volume_is_written_and_really_opens(self, env):
        app = env.make()
        # No extension and a space in the name — both are ordinary user input.
        app._loc_var.set(str(env.tmp_path / "my vault"))
        _set_password(app, PW)
        env.reply(False)                       # "Mount it now?" → Later
        app._do_create()
        assert _pump_until(app, lambda: not app._busy)

        written = env.tmp_path / "my vault.qcv"
        assert written.exists(), ".qcv must be appended when the user omits it"
        assert app._loc_var.get() == str(written)
        _hdr, auth = vol.read_volume_auth_params(str(written))
        assert auth["mode"] == "single"
        vol.VolumeContainer(
            str(written), vol.derive_volume_key_single(PW, auth)).open()

        assert app._pw_var.get() == "" and app._pw2_var.get() == ""
        assert app._err.cget("text") == "✓ Created my vault.qcv"
        assert app._progress._stage_lbl.cget("text") == "Complete"
        assert not app._prog_row.winfo_ismapped()
        assert env.notifications == [
            ("Volume Created", "Encrypted volume saved to my vault.qcv")]
        assert [p for p, _ in env.vm.RecentVolumes.load()] == [str(written)]
        assert app._mode_var.get() == "create"   # the offer to mount was declined

    def test_accepting_the_offer_hands_the_volume_to_the_mount_panel(self, env):
        app = env.make()
        path = env.tmp_path / "handover.qcv"
        app._loc_var.set(str(path))
        _set_password(app, PW)
        app._mount_pw_var.set("stale")
        env.reply(True)                        # "Mount it now?" → Mount now
        app._do_create()
        assert _pump_until(app, lambda: not app._busy)
        assert app._mode_var.get() == "mount"
        assert app._mount_frame.winfo_ismapped()
        assert app._mount_path_var.get() == str(path)
        assert app._mount_pw_var.get() == "", "the stale password must not carry over"
        assert app._vol_info_lbl.cget("text").startswith("Password-protected volume")

    def test_a_unicode_and_very_long_name_survives(self, env):
        app = env.make()
        # Unicode, a shell-quote, an apostrophe, spaces, and a stem long
        # enough to matter — all ordinary things to call a volume.
        stem = "Ω sécurisé — 秘密 it's \"quoted\" " + "v" * 80
        app._loc_var.set(str(env.tmp_path / f"{stem}.qcv"))
        _set_password(app, PW)
        env.reply(False)
        app._do_create()
        assert _pump_until(app, lambda: not app._busy)
        assert (env.tmp_path / f"{stem}.qcv").exists()
        assert app._err.cget("text") == f"✓ Created {stem}.qcv"

    def test_cancelling_during_the_kdf_keeps_the_volume_it_would_replace(
            self, env, monkeypatch, pw_volume):
        """Cancel is checked between core stages, so a cancel during the long
        Argon2 derivation must return before the container is written — the
        volume the user agreed to overwrite has to survive intact."""
        app = env.make()
        before = open(pw_volume, "rb").read()
        in_kdf, release = threading.Event(), threading.Event()
        real_derive = vol.argon2id_derive

        def _slow(secret, salt, *a, **kw):
            in_kdf.set()
            release.wait(15)
            return real_derive(secret, salt, *a, **kw)

        monkeypatch.setattr(vol, "argon2id_derive", _slow)
        app._loc_var.set(pw_volume)
        _set_password(app, PW)
        env.reply(True)                        # Overwrite? → Overwrite
        app._do_create()
        assert in_kdf.wait(15)
        app._request_cancel()
        assert app._err.cget("text").startswith("Cancelling")
        release.set()
        assert _pump_until(app, lambda: not app._busy)

        assert app._err.cget("text") == "Creation cancelled. Nothing was kept."
        assert open(pw_volume, "rb").read() == before
        assert not os.path.exists(pw_volume + ".part")
        assert app.focus_lastfor() is app._loc_entry

    def test_cancelling_a_fresh_creation_leaves_nothing_on_disk(
            self, env, monkeypatch):
        app = env.make()
        path = env.tmp_path / "aborted.qcv"
        in_kdf, release = threading.Event(), threading.Event()
        real_derive = vol.argon2id_derive

        def _slow(secret, salt, *a, **kw):
            in_kdf.set()
            release.wait(15)
            return real_derive(secret, salt, *a, **kw)

        monkeypatch.setattr(vol, "argon2id_derive", _slow)
        app._loc_var.set(str(path))
        _set_password(app, PW)
        app._do_create()
        assert in_kdf.wait(15)
        app._request_cancel()
        release.set()
        assert _pump_until(app, lambda: not app._busy)
        assert not path.exists()
        assert not os.path.exists(str(path) + ".part")
        assert env.notifications == [] and env.vm.RecentVolumes.load() == []

    def test_a_cancel_that_lands_after_the_write_still_discards_the_volume(
            self, env, monkeypatch):
        """The worker re-checks the flag once the core returns, so a cancel
        that lost the race by milliseconds does not leave a volume the user
        believes they cancelled."""
        app = env.make()
        path = env.tmp_path / "raced.qcv"
        real_create = vol.create_volume_single

        def _create_then_cancel(*a, **kw):
            meta = real_create(*a, **kw)
            app._cancel_event.set()
            return meta

        monkeypatch.setattr(vol, "create_volume_single", _create_then_cancel)
        app._loc_var.set(str(path))
        _set_password(app, PW)
        app._do_create()
        assert _pump_until(app, lambda: not app._busy)
        assert not path.exists()
        assert app._err.cget("text") == "Creation cancelled. Nothing was kept."

    def test_a_failure_after_the_cancel_flag_is_reported_as_a_cancel(
            self, env, monkeypatch):
        """The core can raise something other than CancelledOperation on the
        way out of a cancelled run (a half-written file it then removes); with
        the flag set that is a cancellation, not an error to show the user."""
        app = env.make()
        path = env.tmp_path / "boom.qcv"

        def _raise(*a, **kw):
            app._cancel_event.set()
            raise OSError("interrupted")

        monkeypatch.setattr(vol, "create_volume_single", _raise)
        app._loc_var.set(str(path))
        _set_password(app, PW)
        app._do_create()
        assert _pump_until(app, lambda: not app._busy)
        assert app._err.cget("text") == "Creation cancelled. Nothing was kept."
        assert not path.exists()

    def test_cancel_does_nothing_when_no_creation_is_running(self, env):
        app = env.make()
        app._request_cancel()
        assert not app._cancel_event.is_set() and app._err.cget("text") == ""
        app._busy, app._busy_what = True, "mount"
        app._request_cancel()
        assert not app._cancel_event.is_set(), "a mount cannot be cancelled"
        assert app._err.cget("text") == ""
        # …and a creation really is cancellable, so the two refusals above
        # are the guard talking and not a method that never does anything.
        app._busy_what = "create"
        app._request_cancel()
        assert app._cancel_event.is_set()
        assert app._err.cget("text").startswith("Cancelling")
        assert not app._cancel_btn._enabled

    def test_a_missing_destination_folder_is_reported_in_the_form(self, env):
        app = env.make()
        path = env.tmp_path / "no such folder" / "v.qcv"
        app._loc_var.set(str(path))
        _set_password(app, PW)
        app._do_create()
        assert _pump_until(app, lambda: not app._busy)
        assert app._err.cget("text") == ("Couldn't create the volume: File not "
                                         "found. It may have been moved or deleted.")
        assert app.focus_lastfor() is app._loc_entry
        assert not path.exists()

    def test_a_password_below_the_core_floor_is_refused_inline(self, env):
        """The core rejects anything under MIN_PASSWORD_LENGTH, so the form
        checks the same floor before the weak-password prompt — "Use it
        anyway" must never lead to a guaranteed failure."""
        app = env.make()
        path = env.tmp_path / "short.qcv"
        app._loc_var.set(str(path))
        _set_password(app, "a" * (cc.MIN_PASSWORD_LENGTH - 1))
        app._do_create()
        assert app._err.cget("text") == \
            f"Use at least {cc.MIN_PASSWORD_LENGTH} characters."
        assert env.confirms == [], "length is decided before the strength prompt"
        assert app.focus_lastfor() is app._pw_entry
        assert not path.exists()
        assert not app._busy

        # Exactly the minimum gets through the floor (and is still weak).
        _set_password(app, "1" * cc.MIN_PASSWORD_LENGTH)
        env.reply(False)
        app._do_create()
        assert env.confirms == ["Weak password"]
        assert not path.exists()

    def test_closing_the_manager_behind_the_shares_dialog_stops_the_flow(self, env):
        """The shares dialog is modal but the manager can still be closed
        behind it; the rest of ``_on_create_done`` must not touch dead
        widgets or pop another dialog."""
        app = env.make()
        path = str(env.tmp_path / "v.qcv")
        app._loc_var.set(path)

        def _dialog_the_user_walks_away_from(shares, meta):
            app._pending_shares = None
            app._cancel_jobs()
            app.destroy()

        app._show_shares_dialog = _dialog_the_user_walks_away_from
        app._on_create_done(path, {"threshold": 2, "total": 3},
                            shares=_shares_2_of_3())
        assert not app.winfo_exists()
        assert env.confirms == [], "no 'Mount it now?' offer on a dead window"

    def test_a_null_path_in_the_recent_volumes_store_does_not_stop_the_window(
            self, env):
        """The store prefills the mount panel from the constructor; an
        ill-typed entry must read as "nothing recent", not a TypeError that
        turns every Volumes click into "Cannot open window"."""
        import json
        (env.tmp_path / "recent-volumes.json").write_text(
            json.dumps([{"path": None}, {"path": 0}, {"path": {"x": 1}}]))
        app = env.make()
        assert app.winfo_exists()
        assert app._mount_path_var.get() == ""

    def test_a_plain_string_error_is_shown_as_written(self, env):
        app = env.make()
        app._on_create_error("the disk went away")
        assert app._err.cget("text") == "Couldn't create the volume: the disk went away"

    def test_the_end_of_run_handlers_tolerate_a_bar_that_was_never_built(self, env):
        """Both run from ``after`` hops that can outlive the run that made the
        bar, so neither may assume one exists."""
        app = env.make()
        assert app._progress is None
        app._on_create_cancelled()
        assert app._err.cget("text") == "Creation cancelled. Nothing was kept."
        app._on_create_error(ValueError("nope"))
        assert app._err.cget("text") == "Couldn't create the volume: nope"


# ── Recovery-shares dialog ───────────────────────────────────────────────────

@requires_tkinter
class TestSharesDialog:
    """The shares are the only key to a split-key volume, so this screen holds
    them on the window until they are saved and refuses to close quietly."""

    def _open(self, env, k=2, n=3):
        app = env.make()
        app._loc_var.set(str(env.tmp_path / "vault.qcv"))
        shares = _shares_2_of_3()[:n]
        app._show_shares_dialog(shares, {"threshold": k, "total": n})
        win = _toplevel(app, "Recovery Shares")
        assert win is not None
        return app, win, shares

    def test_every_share_is_shown_with_the_threshold(self, env, nomodal):
        app, win, shares = self._open(env)
        texts = _widget_texts(win)
        assert "You need 2 of 3 shares to unlock this volume." in texts
        assert [f"Share {i} of 3" for i in (1, 2, 3)] == \
            [t for t in texts if t.startswith("Share ")]
        # The codes themselves live in Text widgets, not labels.
        assert set(shares) <= set(_text_contents(win))
        assert app._pending_shares == shares

    def test_metadata_without_a_threshold_falls_back_to_k_2_and_the_count(
            self, env, nomodal):
        """``create_volume_shamir`` returns threshold/total, but the dialog is
        also reachable from ``_on_create_done`` with whatever meta the core
        handed back — a missing pair must not render "None of None"."""
        app = env.make()
        app._loc_var.set("")                      # …and no chosen filename yet
        shares = _shares_2_of_3()
        app._show_shares_dialog(shares, {})
        win = _toplevel(app, "Recovery Shares")
        texts = _widget_texts(win)
        assert "You need 2 of 3 shares to unlock this volume." in texts
        assert [t for t in texts if t.startswith("Share ")] == \
            ["Share 1 of 3", "Share 2 of 3", "Share 3 of 3"]
        # With no filename to name, the leave-guard says "the volume".
        env.reply(False)
        _button(win, "I've saved all shares")._fire()
        assert "Without them, the volume can never be opened again" in \
            env.confirm_msgs[-1]
        assert win.winfo_exists() and app._pending_shares == shares

    def test_copy_puts_the_share_on_the_clipboard_and_says_so(self, env, nomodal):
        app, win, shares = self._open(env)
        btn = _button(win, "Copy")
        btn._fire()
        assert win.clipboard_get() == shares[0]
        assert btn.cget("text") == "✓ Copied"
        # The label goes back to "Copy" on its own.
        assert _pump_until(app, lambda: btn.cget("text") == "Copy", 4)

    def test_command_c_on_a_share_text_is_a_concealed_timed_copy(self, env, nomodal):
        """Select-all + ⌘C on the share (or the context menu's Copy, which
        raises the same <<Copy>>) must arm the countdown like the button —
        Tk's stock handler would hand a clipboard manager the share for ever."""
        app, win, shares = self._open(env)
        txt = _text_widgets(win)[0]
        assert txt.get("1.0", "end").strip() == shares[0]
        win.clipboard_clear()
        txt.tag_add("sel", "1.0", "end")
        txt.event_generate("<<Copy>>")
        app.update()
        assert win.clipboard_get() == shares[0]
        assert any(t.startswith("Clipboard clears in") for t in _widget_texts(win))
        assert _button(win, "✓ Copied") is not None
        # And the leave-guard knows a copy happened.
        env.reply(False)
        _button(win, "I've saved all shares")._fire()
        assert "Copying isn't enough" in env.confirm_msgs[-1]

    def test_a_refused_clipboard_is_reported_on_the_button(self, env, nomodal):
        import tkinter as tk
        app, win, shares = self._open(env)
        btn = _button(win, "Copy")
        win.clipboard_clear = lambda: (_ for _ in ()).throw(tk.TclError("owned"))
        btn._fire()
        assert btn.cget("text") == "✗ Failed"

    def test_save_all_writes_a_private_file_that_parses_back_to_the_shares(
            self, env, nomodal):
        from quantacrypt.core import package as pkg
        from quantacrypt.ui.volume_manager import _parse_share_text
        app, win, shares = self._open(env)
        target = env.tmp_path / "vault.shares.txt"
        env.saveas = str(target)
        _button(win, "Save all shares…")._fire()

        assert target.exists()
        assert oct(target.stat().st_mode & 0o777) == "0o600"
        body = target.read_text()
        assert body.startswith("QuantaCrypt recovery shares: 2 of 3 needed")
        assert pkg.normalize_shares(_parse_share_text(body)) == shares
        note = [t for t in _widget_texts(win) if t.startswith("✓ Saved all 3 shares")]
        assert note and "vault.shares.txt" in note[0]
        # The last dialog call was the save picker, seeded with a sensible name.
        kind, kw = env.dialog_calls[-1]
        assert kind == "asksaveasfilename" and kw["initialfile"] == "vault.shares.txt"

    def test_cancelling_the_save_picker_writes_nothing(self, env, nomodal):
        app, win, _shares = self._open(env)
        env.saveas = ""
        _button(win, "Save all shares…")._fire()
        # It got as far as the picker and stopped there — nothing on disk,
        # nothing claimed on screen.
        assert env.dialog_calls[-1][0] == "asksaveasfilename"
        assert list(env.tmp_path.glob("*.txt")) == []
        assert not any(t.startswith("✓ Saved") for t in _widget_texts(win))

    def test_an_existing_file_of_that_name_is_never_overwritten(self, env, nomodal):
        app, win, shares = self._open(env)
        target = env.tmp_path / "vault.shares.txt"
        target.write_text("someone else's only key material")
        env.saveas = str(target)
        _button(win, "Save all shares…")._fire()
        assert target.read_text() == "someone else's only key material"
        second = env.tmp_path / "vault.shares_2.txt"
        assert second.exists() and shares[0] in second.read_text()
        note = [t for t in _widget_texts(win) if t.startswith("✓ Saved all 3 shares")]
        assert note and "already existed" in note[0] and "vault.shares_2.txt" in note[0]

    def test_a_failed_save_is_reported_and_leaves_the_dialog_unsaved(
            self, env, nomodal):
        app, win, _shares = self._open(env)
        env.saveas = str(env.tmp_path / "missing dir" / "s.txt")
        _button(win, "Save all shares…")._fire()
        assert [t for t, _ in env.alerts] == ["Couldn't save the shares"]
        # Nothing half-written anywhere, and nothing claimed on screen.
        assert list(env.tmp_path.rglob("*.txt")) == []
        assert not any(t.startswith("✓ Saved") for t in _widget_texts(win))
        # Still unsaved → leaving must still ask.
        env.reply(False)
        _button(win, "I've saved all shares")._fire()
        assert win.winfo_exists() and app._pending_shares is not None

    def test_leaving_without_saving_asks_first(self, env, nomodal):
        app, win, _shares = self._open(env)
        env.reply(False)
        _button(win, "I've saved all shares")._fire()
        assert env.confirms == ["Shares not saved"]
        assert win.winfo_exists(), "Go back must keep the dialog up"
        assert app._pending_shares is not None
        env.reply(True)
        _button(win, "I've saved all shares")._fire()
        assert not win.winfo_exists()
        assert app._pending_shares is None

    def test_the_warning_mentions_the_clipboard_only_after_a_copy(
            self, env, nomodal):
        app, win, _shares = self._open(env)
        env.reply(False)
        _button(win, "I've saved all shares")._fire()
        assert "clipboard" not in env.confirm_msgs[-1]
        _button(win, "Copy")._fire()
        env.reply(False)
        _button(win, "I've saved all shares")._fire()
        assert "clipboard clears in 60 seconds" in env.confirm_msgs[-1]

    def test_saving_first_lets_the_dialog_close_without_a_question(
            self, env, nomodal):
        app, win, _shares = self._open(env)
        env.saveas = str(env.tmp_path / "vault.shares.txt")
        _button(win, "Save all shares…")._fire()
        _button(win, "I've saved all shares")._fire()
        assert env.confirms == []
        assert not win.winfo_exists() and app._pending_shares is None

    def test_the_close_box_goes_through_the_same_guard(self, env, nomodal):
        """Escape and the window's close box are both wired to ``_finish``;
        the close box is the one a test can fire without depending on which
        window the window manager has given the keyboard to."""
        app, win, _shares = self._open(env)
        env.reply(False)
        win.tk.call(win.protocol("WM_DELETE_WINDOW"))
        assert env.confirms == ["Shares not saved"]
        assert win.winfo_exists() and app._pending_shares is not None
        env.reply(True)
        win.tk.call(win.protocol("WM_DELETE_WINDOW"))
        assert not win.winfo_exists()
        assert app._pending_shares is None


# ── Setup screen (FUSE missing) ──────────────────────────────────────────────

def _setup_app(env, components=None, mount=True):
    """A manager whose FUSE components are missing.  ``mount=True`` also
    switches to the Mount Existing panel so the setup screen is actually
    mapped (``winfo_ismapped`` is False for a panel that is packed away)."""
    env.components = {k: dict(v) for k, v in
                      (components or _Env.MISSING_COMPONENTS).items()}
    app = env.make()
    if mount:
        app._mode_var.set("mount")
        app.update()
    return app


@requires_tkinter
class TestSetupScreen:
    """With a FUSE component missing the mount panel is replaced by a guided
    setup screen, and the create panel carries a warning strip."""

    def test_the_mount_panel_is_replaced_by_the_setup_screen(self, env):
        app = _setup_app(env)
        app._mode_var.set("mount")
        app.update()
        assert app._setup_frame.winfo_ismapped()
        assert not app._mount_inner.winfo_ismapped()
        texts = _widget_texts(app._setup_frame)
        assert "Setup Required" in texts
        assert any("Disk mounting support" in t for t in texts)
        assert any("Mounting helper (fusepy)" in t for t in texts)
        assert "fusepy is not installed" in texts
        assert app._comp_widgets["fusepy"]["icon_lbl"].cget("text") == "✗"

    def test_the_create_panel_warns_and_offers_a_way_over(self, env):
        app = _setup_app(env, mount=False)
        assert app._fuse_warn.outer.winfo_ismapped()
        _button(app._fuse_warn, "Set up →")._fire()
        assert app._mode_var.get() == "mount"

    def test_opening_straight_into_setup_puts_the_keyboard_on_check_again(
            self, env, pw_volume):
        env.components = dict(_Env.MISSING_COMPONENTS)
        app = env.make(volume_path=pw_volume)
        assert _pump_until(app, lambda: app.focus_lastfor() is app._recheck_btn, 3)

    def test_switching_to_the_setup_screen_leaves_the_keyboard_behind(self, env):
        """Documents current behaviour: ``_on_mode_change`` focuses before Tk
        has mapped the frame it just packed, so ``_focus_first`` cannot see
        the setup screen and the keyboard lands on the hidden volume-path
        field instead.  Reported as a defect."""
        app = _setup_app(env, mount=False)
        # The window has already focused the create panel's first field.
        assert _pump_until(app, lambda: app.focus_lastfor() is app._loc_entry, 3)
        app._mode_var.set("mount")
        app.update()
        assert app.focus_lastfor() is app._loc_entry, \
            "focus never left the create panel"
        # Once the frame really is mapped the same call gets it right.
        app._focus_first()
        assert app.focus_lastfor() is app._recheck_btn

    def test_rechecking_while_still_missing_names_what_is_missing(self, env):
        app = _setup_app(env)
        _button(app._setup_frame, "Check again")._fire()
        assert app._recheck_lbl.cget("text") == (
            "Checked just now. Still missing: Mounting helper, Disk mounting support.")
        assert app._setup_frame.winfo_ismapped()

    def test_rechecking_after_a_partial_install_updates_only_that_row(self, env):
        app = _setup_app(env)
        env.components = {"fusepy": {"ok": True, "detail": "fusepy is installed"},
                          "fuse_backend": {"ok": False, "detail": "No FUSE backend found"}}
        _button(app._setup_frame, "Check again")._fire()
        assert app._comp_widgets["fusepy"]["icon_lbl"].cget("text") == "✓"
        assert app._comp_widgets["fusepy"]["detail_lbl"].cget("text") == "fusepy is installed"
        assert app._comp_widgets["fuse_backend"]["icon_lbl"].cget("text") == "✗"
        assert app._recheck_lbl.cget("text").endswith("Still missing: Disk mounting support.")
        assert not app._fuse_ok

    def test_a_component_with_no_row_is_skipped(self, env):
        """check_fuse_components may gain a key this build has no row for;
        the recheck must skip it rather than crash on a missing widget."""
        app = _setup_app(env)
        env.components = {**_Env.MISSING_COMPONENTS,
                          "future_backend": {"ok": True, "detail": "brand new"}}
        _button(app._setup_frame, "Check again")._fire()
        assert set(app._comp_widgets) == {"fusepy", "fuse_backend"}
        assert app._recheck_lbl.cget("text").startswith("Checked just now")
        assert not app._fuse_ok

    def test_rechecking_once_everything_is_present_reveals_the_mount_panel(self, env):
        app = _setup_app(env)
        app._mode_var.set("mount")
        app.update()
        env.components = dict(_Env.OK_COMPONENTS)
        _button(app._setup_frame, "Check again")._fire()
        app.update()
        assert app._fuse_ok
        assert not app._setup_frame.winfo_ismapped()
        assert app._mount_inner.winfo_ismapped()
        assert not app._fuse_warn.outer.winfo_ismapped()

    def test_installing_the_helper_reports_success_and_rechecks(
            self, env, monkeypatch):
        app = _setup_app(env)
        calls = []

        def _run(cmd, **kw):
            calls.append(cmd)
            return SimpleNamespace(returncode=0, stderr="", stdout="")

        monkeypatch.setattr(env.vm.subprocess, "run", _run)
        env.component_queue = [{"fusepy": {"ok": True, "detail": "fusepy is installed"},
                                "fuse_backend": {"ok": False,
                                                 "detail": "No FUSE backend found"}}]
        _button(app._setup_frame, "Install helper")._fire()
        assert app._comp_widgets["fusepy"]["detail_lbl"].cget("text").startswith(
            "Installing…")
        assert _pump_until(
            app, lambda: app._comp_widgets["fusepy"]["icon_lbl"].cget("text") == "✓")
        assert calls == [[sys.executable, "-m", "pip", "install", "fusepy"]]
        assert app._comp_widgets["fusepy"]["detail_lbl"].cget("text") == \
            "fusepy is installed"
        assert not app._comp_widgets["fusepy"]["btn"].winfo_ismapped()
        assert "fusepy" not in app._tickers

    def test_a_failed_install_shows_the_last_stderr_line_and_re_arms_the_button(
            self, env, monkeypatch):
        app = _setup_app(env)
        monkeypatch.setattr(
            env.vm.subprocess, "run",
            lambda cmd, **kw: SimpleNamespace(
                returncode=1, stderr="warning: whatever\nERROR: no matching distribution",
                stdout=""))
        btn = _button(app._setup_frame, "Install helper")
        btn._fire()
        assert _pump_until(
            app,
            lambda: app._comp_widgets["fusepy"]["detail_lbl"].cget("text").startswith(
                "Install failed"))
        assert app._comp_widgets["fusepy"]["detail_lbl"].cget("text") == \
            "Install failed: ERROR: no matching distribution"
        assert btn._enabled, "the user must be able to try again"
        assert "fusepy" not in app._tickers

    def test_an_install_that_fails_without_stderr_still_says_something(
            self, env, monkeypatch):
        app = _setup_app(env)
        monkeypatch.setattr(
            env.vm.subprocess, "run",
            lambda cmd, **kw: SimpleNamespace(returncode=2, stderr="   ", stdout=""))
        _button(app._setup_frame, "Install helper")._fire()
        assert _pump_until(
            app,
            lambda: app._comp_widgets["fusepy"]["detail_lbl"].cget("text") ==
            "Install failed: Unknown error")

    def test_an_install_that_cannot_start_reports_the_failure(
            self, env, monkeypatch):
        """``_run_install`` used to hand the exception to ``after`` as
        ``lambda: ... str(e)``; Python unbinds ``e`` when the except block
        ends, so the callback raised NameError, the failure was never
        rendered, the elapsed ticker kept counting and the button stayed
        disabled.  (The earlier version of this test pinned that stuck state
        by watching the ticker read exactly "1s", which is how it became the
        one flaky test in CI.)"""
        app = _setup_app(env)

        def _boom(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, 120)

        monkeypatch.setattr(env.vm.subprocess, "run", _boom)
        btn = _button(app._setup_frame, "Install helper")
        btn._fire()
        assert _pump_until(
            app,
            lambda: app._comp_widgets["fusepy"]["detail_lbl"].cget("text").startswith(
                "Install failed"))
        assert "timed out" in app._comp_widgets["fusepy"]["detail_lbl"].cget("text")
        assert btn._enabled, "the user must be able to try again"
        assert "fusepy" not in app._tickers

    def test_a_bundled_copy_points_at_a_re_download_instead_of_pip(
            self, env, monkeypatch):
        """Inside a PyInstaller bundle sys.executable is the app itself, so
        "-m pip" would respawn QuantaCrypt; fusepy ships in the bundle, so a
        missing import means a damaged install."""
        opened = []
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(env.vm.webbrowser, "open", lambda url: opened.append(url))
        app = _setup_app(env)
        assert app._comp_widgets["fusepy"]["detail_lbl"].cget("text") == (
            "The helper ships inside the app. This copy is damaged. "
            "Download QuantaCrypt again to fix it.")
        assert _text_contents(app._comp_widgets["fusepy"]["cmd_box"]) == [""]
        _button(app._setup_frame, "Get QuantaCrypt again")._fire()
        assert opened == [env.vm._RELEASES_URL]

    def test_the_backend_row_shows_the_brew_command_and_can_open_terminal(
            self, env, monkeypatch):
        popens = []
        monkeypatch.setattr(env.vm.sys, "platform", "darwin")
        monkeypatch.setattr(env.vm.shutil, "which", lambda name: "/opt/homebrew/bin/brew")
        monkeypatch.setattr(env.vm.subprocess, "Popen", lambda cmd: popens.append(cmd))
        app = _setup_app(env)
        _button(app._setup_frame, "How to install…")._fire()
        box = app._comp_widgets["fuse_backend"]["cmd_box"]
        app.update()
        assert box.get("1.0", "end").strip() == "brew install --cask fuse-t"
        assert box.winfo_ismapped()
        assert "FUSE-T is recommended" in \
            app._comp_widgets["fuse_backend"]["detail_lbl"].cget("text")
        assert app._recheck_lbl.cget("text") == "When it's installed, click Check again."

        term = _button(app._setup_frame, "Open in Terminal")
        term._fire()
        assert popens and popens[0][0] == "osascript"
        assert "brew install --cask fuse-t" in popens[0][2]
        assert app._comp_widgets["fuse_backend"]["detail_lbl"].cget("text").startswith(
            "Check Terminal")
        assert not term._enabled

    def test_a_terminal_that_will_not_open_says_so(self, env, monkeypatch):
        monkeypatch.setattr(env.vm.sys, "platform", "darwin")
        monkeypatch.setattr(env.vm.shutil, "which", lambda name: "/opt/homebrew/bin/brew")
        app = _setup_app(env)
        _button(app._setup_frame, "How to install…")._fire()
        monkeypatch.setattr(env.vm.subprocess, "Popen",
                            lambda cmd: (_ for _ in ()).throw(OSError("no osascript")))
        _button(app._setup_frame, "Open in Terminal")._fire()
        assert app._comp_widgets["fuse_backend"]["detail_lbl"].cget("text") == (
            "Couldn't open Terminal. Copy the command above and run it yourself.")
        assert "fuse_backend" not in app._tickers

    def test_without_homebrew_the_row_offers_the_installers(self, env, monkeypatch):
        monkeypatch.setattr(env.vm.sys, "platform", "darwin")
        monkeypatch.setattr(env.vm.shutil, "which", lambda name: None)
        app = _setup_app(env)
        _button(app._setup_frame, "How to install…")._fire()
        body = app._comp_widgets["fuse_backend"]["cmd_box"].get("1.0", "end")
        assert env.vm._FUSE_T_URL in body and env.vm._MACFUSE_URL in body
        assert "Homebrew isn't installed" in \
            app._comp_widgets["fuse_backend"]["detail_lbl"].cget("text")

    def test_windows_is_told_volumes_are_not_supported(self, env, monkeypatch):
        monkeypatch.setattr(env.vm.sys, "platform", "win32")
        app = _setup_app(env)
        _button(app._setup_frame, "How to install…")._fire()
        app.update()
        assert app._comp_widgets["fuse_backend"]["detail_lbl"].cget("text") == \
            "Encrypted volumes aren't supported on Windows yet."
        assert not app._comp_widgets["fuse_backend"]["cmd_box"].winfo_ismapped()

    def test_linux_gets_its_package_manager_commands(self, env, monkeypatch):
        monkeypatch.setattr(env.vm.sys, "platform", "linux")
        app = _setup_app(env)
        _button(app._setup_frame, "How to install…")._fire()
        box = app._comp_widgets["fuse_backend"]["cmd_box"]
        body = box.get("1.0", "end")
        assert "apt install libfuse-dev" in body
        assert "dnf install fuse" in body and "pacman -S fuse2" in body
        assert int(box.cget("height")) == 3, "the box grows to fit every line"

    def test_the_command_box_is_read_only_and_sized_to_its_content(self, env):
        app = _setup_app(env)
        box = app._comp_widgets["fusepy"]["cmd_box"]
        app._set_cmd_box(box, "one line")
        assert box.get("1.0", "end").strip() == "one line"
        assert int(box.cget("height")) == 1
        assert str(box.cget("state")) == "disabled"
        app._set_cmd_box(box, "a\nb\nc\nd")
        assert int(box.cget("height")) == 4
        assert box.get("1.0", "end").strip() == "a\nb\nc\nd"
        # Empty is the floor: one row, and the previous content is gone.
        app._set_cmd_box(box, "")
        assert int(box.cget("height")) == 1
        assert box.get("1.0", "end").strip() == ""

    def test_the_elapsed_ticker_counts_and_stops(self, env):
        app = _setup_app(env)
        app._start_ticker("fusepy", "Installing…")
        assert app._comp_widgets["fusepy"]["detail_lbl"].cget("text") == "Installing… 0s"
        assert "fusepy" in app._tickers
        app._stop_ticker("fusepy")
        assert "fusepy" not in app._tickers
        # A second stop is a no-op, not an error.
        app._stop_ticker("fusepy")

    def test_starting_a_ticker_twice_keeps_one_timer(self, env):
        app = _setup_app(env)
        app._start_ticker("fusepy", "Installing…")
        first = app._tickers["fusepy"]
        first_job = first["job"]
        assert first_job is not None
        app._start_ticker("fusepy", "Still going…")
        assert app._tickers["fusepy"] is not first
        assert app._comp_widgets["fusepy"]["detail_lbl"].cget("text") == "Still going… 0s"
        # The first timer was really cancelled, not just forgotten: Tk no
        # longer lists its id, so the old base can never overwrite the new
        # one a second from now.
        pending = app.tk.splitlist(app.tk.call("after", "info"))
        assert first_job not in pending
        assert app._tickers["fusepy"]["job"] in pending


# ── Volume selection ─────────────────────────────────────────────────────────

@requires_tkinter
class TestVolumeSelection:
    """Choosing a .qcv reads its cleartext auth params to pick the unlock mode,
    describe the volume and suggest a mount point."""

    def _mount_app(self, env):
        app = env.make()
        app._mode_var.set("mount")
        app.update()
        return app

    def test_a_password_volume_is_described_with_its_size(self, env, pw_volume):
        app = self._mount_app(env)
        app._mount_path_var.set(pw_volume)
        assert app._mount_auth_var.get() == "password"
        text = app._vol_info_lbl.cget("text")
        assert text.startswith("Password-protected volume  ·  file on disk ")
        assert app._mount_pw_frame.winfo_ismapped()

    def test_a_split_key_volume_names_its_threshold(self, env):
        path = str(env.tmp_path / "split.qcv")
        vol.create_volume_shamir(path, 5, 3)
        app = self._mount_app(env)
        app._mount_path_var.set(path)
        app.update()
        assert app._mount_auth_var.get() == "shamir"
        assert app._vol_info_lbl.cget("text").startswith(
            "Split-key volume: needs 3 of 5 shares  ·  file on disk ")
        assert app._mount_shares_frame.winfo_ismapped()

    def test_a_missing_file_is_only_complained_about_once_the_field_is_left(
            self, env):
        app = self._mount_app(env)
        app._mount_path_var.set(str(env.tmp_path / "ghost.qcv"))
        assert app._vol_info_lbl.cget("text") == "", "no error per keystroke"
        app._on_volume_selected(show_errors=True)
        assert app._vol_info_lbl.cget("text") == "That file doesn't exist."

    def test_a_file_that_is_not_a_volume_is_named_on_leaving_the_field(self, env):
        junk = env.tmp_path / "notes.txt"
        junk.write_bytes(b"this is not a volume")
        app = self._mount_app(env)
        app._mount_path_var.set(str(junk))
        assert app._vol_info_lbl.cget("text") == ""
        app._on_volume_selected(show_errors=True)
        assert app._vol_info_lbl.cget("text") == "Not a valid .qcv file"

    def test_an_empty_path_clears_the_description(self, env, pw_volume):
        app = self._mount_app(env)
        app._mount_path_var.set(pw_volume)
        assert app._vol_info_lbl.cget("text") != ""
        app._mount_path_var.set("")
        assert app._vol_info_lbl.cget("text") == ""

    def test_the_size_hint_is_dropped_when_the_file_vanishes_mid_check(
            self, env, pw_volume, monkeypatch):
        """isfile and getsize are two syscalls; a file deleted in between must
        still describe the volume, just without a size."""
        app = self._mount_app(env)
        monkeypatch.setattr(env.vm.os.path, "getsize",
                            lambda p: (_ for _ in ()).throw(OSError("gone")))
        app._mount_path_var.set(pw_volume)
        assert app._vol_info_lbl.cget("text") == "Password-protected volume"

    def test_the_suggested_mount_point_never_clobbers_a_typed_one(
            self, env, pw_volume):
        app = self._mount_app(env)
        app._mount_path_var.set(pw_volume)
        suggested = app._mount_point_var.get()
        assert suggested.endswith(os.path.join("QuantaCrypt Volumes", "vault"))

        # Our own previous suggestion is replaced …
        other = str(env.tmp_path / "second.qcv")
        vol.create_volume_single(other, PW)
        app._mount_path_var.set(other)
        assert app._mount_point_var.get().endswith(
            os.path.join("QuantaCrypt Volumes", "second"))

        # … but anything the user typed is left alone.
        app._mount_point_var.set("/Users/me/somewhere else")
        app._mount_path_var.set(pw_volume)
        assert app._mount_point_var.get() == "/Users/me/somewhere else"

    def test_the_default_mount_point_falls_back_to_a_name(self, env):
        app = env.make()
        assert app._default_mount_point("/tmp/a b/vault.qcv") == \
            os.path.expanduser(os.path.join("~", "QuantaCrypt Volumes", "vault"))
        assert app._default_mount_point("/tmp/dir/") == \
            os.path.expanduser(os.path.join("~", "QuantaCrypt Volumes", "Volume"))


# ── Loading shares from files ────────────────────────────────────────────────

@requires_tkinter
class TestLoadSharesFromFiles:
    """"Load from files…" appends every share it finds to the box, one per
    line, skipping the ones already there."""

    def _app(self, env):
        app = env.make()
        app._mode_var.set("mount")
        app._mount_auth_var.set("shamir")
        app.update()
        return app

    def _box(self, app):
        return [ln for ln in app._mount_shares_text.get("1.0", "end").splitlines()
                if ln.strip()]

    def test_shares_from_two_files_are_appended_one_per_line(self, env):
        app = self._app(env)
        shares = _shares_2_of_3()
        a = env.tmp_path / "a.txt"
        a.write_text(f"QuantaCrypt Key Shares\nShare 1 of 3:\n{shares[0]}\n")
        b = env.tmp_path / "b.txt"
        b.write_text(f"Share 2 of 3:\n{shares[1]}\n")
        env.openfiles = (str(a), str(b))
        app._load_mount_shares_from_files()
        assert self._box(app) == [shares[0], shares[1]]
        assert app._mount_status.cget("text") == "Loaded 2 shares from those files."
        assert app._mount_err.cget("text") == ""
        assert app.focus_lastfor() is app._mount_shares_text

    def test_a_single_file_is_described_in_the_singular(self, env):
        app = self._app(env)
        share = _shares_2_of_3()[0]
        f = env.tmp_path / "one.txt"
        f.write_text(share)
        env.openfiles = (str(f),)
        app._load_mount_shares_from_files()
        assert self._box(app) == [share]
        assert app._mount_status.cget("text") == "Loaded 1 share from that file."

    def test_shares_already_in_the_box_are_counted_not_repeated(self, env):
        app = self._app(env)
        shares = _shares_2_of_3()
        app._mount_shares_text.insert("1.0", shares[0] + "\n")
        f = env.tmp_path / "both.txt"
        f.write_text("\n".join(shares[:2]))
        env.openfiles = (str(f),)
        app._load_mount_shares_from_files()
        assert self._box(app) == [shares[0], shares[1]]
        assert app._mount_status.cget("text") == \
            "Loaded 1 share from that file. 1 already in the box."

    def test_a_file_holding_only_shares_already_present_adds_nothing(self, env):
        app = self._app(env)
        share = _shares_2_of_3()[0]
        app._mount_shares_text.insert("1.0", share)
        f = env.tmp_path / "dupe.txt"
        f.write_text(share)
        env.openfiles = (str(f),)
        app._load_mount_shares_from_files()
        assert self._box(app) == [share]
        assert app._mount_status.cget("text") == \
            "Loaded 0 shares from that file. 1 already in the box."

    def test_cancelling_the_picker_changes_nothing(self, env):
        app = self._app(env)
        app._mount_shares_text.insert("1.0", "a line the user typed\n")
        env.openfiles = ()
        app._load_mount_shares_from_files()
        # The picker did open — an empty selection is what stopped it — and
        # the box was left exactly as the user had it.
        assert env.dialog_calls[-1][0] == "askopenfilenames"
        assert self._box(app) == ["a line the user typed"]
        assert app._mount_status.cget("text") == ""
        assert app._mount_err.cget("text") == ""
        assert env.alerts == []

    def test_a_file_with_no_shares_says_so_and_leaves_the_box_alone(self, env):
        app = self._app(env)
        f = env.tmp_path / "prose.txt"
        f.write_text("just some notes about where I hid the shares")
        env.openfiles = (str(f),)
        app._load_mount_shares_from_files()
        assert [t for t, _ in env.alerts] == ["No shares found"]
        assert "that file" in env.alerts[0][1]
        assert self._box(app) == []

    def test_an_oversized_file_is_refused_without_being_read(self, env):
        app = self._app(env)
        share = _shares_2_of_3()[0]
        big = env.tmp_path / "huge.txt"
        # One byte over the cap, and the share is inside it: the refusal has
        # to be the size, not a parse that found nothing.
        body = share + "\n"
        big.write_text(body + "x" * ((1 << 20) + 1 - len(body)))
        assert big.stat().st_size == (1 << 20) + 1
        env.openfiles = (str(big),)
        app._load_mount_shares_from_files()
        assert app._mount_err.cget("text") == "Couldn't read huge.txt."
        assert [t for t, _ in env.alerts] == ["No shares found"]
        assert self._box(app) == []

    def test_a_file_exactly_on_the_cap_is_still_read(self, env):
        """The other side of the boundary — ``> _MAX_SHARE_FILE`` rejects, so
        exactly the cap must load."""
        from quantacrypt.ui.volume_manager import _MAX_SHARE_FILE
        app = self._app(env)
        share = _shares_2_of_3()[0]
        edge = env.tmp_path / "exact.txt"
        body = share + "\n"
        edge.write_text(body + "x" * (_MAX_SHARE_FILE - len(body)))
        assert edge.stat().st_size == _MAX_SHARE_FILE
        env.openfiles = (str(edge),)
        app._load_mount_shares_from_files()
        assert self._box(app) == [share]
        assert app._mount_err.cget("text") == ""
        assert env.alerts == []

    def test_an_unreadable_file_loses_its_warning_when_another_file_works(self, env):
        """Documents current behaviour: the 'Couldn't read …' line is written
        and then unconditionally cleared a few lines later, so a partly
        unreadable selection loads silently.  Reported as a defect."""
        app = self._app(env)
        share = _shares_2_of_3()[0]
        folder = env.tmp_path / "a folder"
        folder.mkdir()
        good = env.tmp_path / "good.txt"
        good.write_text(share)
        env.openfiles = (str(folder), str(good))
        app._load_mount_shares_from_files()
        assert self._box(app) == [share]
        assert app._mount_err.cget("text") == ""     # the warning is gone
        assert app._mount_status.cget("text") == "Loaded 1 share from those files."

    def test_the_picker_is_not_opened_while_a_mount_is_running(self, env):
        app = self._app(env)
        share = _shares_2_of_3()[0]
        f = env.tmp_path / "later.txt"
        f.write_text(share)
        env.openfiles = (str(f),)
        app._busy = True
        app._load_mount_shares_from_files()
        assert env.dialog_calls == []
        assert self._box(app) == []
        # The busy flag is the reason — the same call once the mount ends
        # opens the picker and loads the file.
        app._busy = False
        app._load_mount_shares_from_files()
        assert [k for k, _ in env.dialog_calls] == ["askopenfilenames"]
        assert self._box(app) == [share]

    def test_the_picker_starts_beside_the_chosen_volume(self, env, pw_volume):
        app = self._app(env)
        app._mount_path_var.set(pw_volume)
        env.openfiles = ()
        app._load_mount_shares_from_files()
        kind, kw = env.dialog_calls[-1]
        assert kind == "askopenfilenames"
        assert kw["initialdir"] == os.path.dirname(pw_volume)

    def test_with_no_volume_chosen_the_picker_starts_at_home(self, env):
        app = self._app(env)
        app._mount_path_var.set("")
        env.openfiles = ()
        app._load_mount_shares_from_files()
        _kind, kw = env.dialog_calls[-1]
        assert kw["initialdir"] == os.path.expanduser("~")


# ── Mounting ─────────────────────────────────────────────────────────────────

@requires_tkinter
class TestMountValidation:
    """What ``_do_mount`` refuses before it starts a worker."""

    def _app(self, env, pw_volume=None):
        app = env.make(volume_path=pw_volume) if pw_volume else env.make()
        app._mode_var.set("mount")
        app.update()
        return app

    def test_a_second_click_while_busy_is_ignored(self, env, pw_volume):
        app = self._app(env, pw_volume)
        app._mount_err.config(text="previous message")
        app._busy = True
        app._do_mount()
        assert app._mount_err.cget("text") == "previous message"
        assert env.mount_calls == []
        # …and the flag is the reason: the same click with it down reaches
        # the credential check.
        app._busy = False
        app._do_mount()
        assert app._mount_err.cget("text") == "Enter the password."
        assert env.mount_calls == []

    def test_a_path_that_is_not_a_file_is_refused(self, env):
        app = self._app(env)
        app._mount_path_var.set(str(env.tmp_path / "ghost.qcv"))
        app._mount_point_var.set(str(env.tmp_path / "mnt"))
        app._do_mount()
        assert app._mount_err.cget("text") == "Select a valid .qcv file."
        assert app.focus_lastfor() is app._mount_path_entry
        assert env.mount_calls == []

    def test_an_empty_path_is_refused(self, env):
        app = self._app(env)
        app._mount_path_var.set("   ")
        app._do_mount()
        assert app._mount_err.cget("text") == "Select a valid .qcv file."

    def test_an_empty_mount_point_is_refused(self, env, pw_volume):
        app = self._app(env, pw_volume)
        app._mount_point_var.set("  ")
        app._mount_pw_var.set(PW)
        app._do_mount()
        assert app._mount_err.cget("text") == "Choose a mount point."
        assert app.focus_lastfor() is app._mount_point_entry
        assert env.mount_calls == []

    def test_a_missing_password_is_refused(self, env, pw_volume):
        app = self._app(env, pw_volume)
        app._mount_point_var.set(str(env.tmp_path / "mnt"))
        app._do_mount()
        assert app._mount_err.cget("text") == "Enter the password."
        assert app.focus_lastfor() is app._mount_pw_entry
        assert env.mount_calls == []

    def test_missing_shares_are_refused(self, env, pw_volume):
        app = self._app(env, pw_volume)
        app._mount_auth_var.set("shamir")
        app.update()
        app._mount_point_var.set(str(env.tmp_path / "mnt"))
        app._do_mount()
        assert app._mount_err.cget("text") == "Paste your recovery shares."
        assert app.focus_lastfor() is app._mount_shares_text
        assert env.mount_calls == []


@requires_tkinter
class TestMountRun:
    """A mount that runs: the key is derived from what the user typed, the
    volume really opens with it, and the screen reports the outcome."""

    def _ready(self, env, path, name="mnt"):
        app = env.make(volume_path=path)
        app._mount_point_var.set(str(env.tmp_path / name))
        return app, str(env.tmp_path / name)

    def test_mounting_a_password_volume_lists_it_with_live_statistics(
            self, env, pw_volume):
        app, mp = self._ready(env, pw_volume)
        app._mount_pw_var.set(PW)
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert env.mount_calls == [(pw_volume, mp)]
        assert os.path.isdir(mp)
        assert app._mount_status.cget("text") == f"✓ Mounted at {mp}"
        assert app._mount_pw_var.get() == ""
        assert app._mount_prog._stage_lbl.cget("text") == "Complete"
        assert env.notifications == [
            ("Volume Mounted", f"Encrypted volume mounted at {mp}")]
        assert [p for p, _ in env.vm.RecentVolumes.load()] == [pw_volume]
        texts = _widget_texts(app._mounted_list_frame)
        assert "MOUNTED VOLUMES" in texts and "vault.qcv" in texts and mp in texts
        assert any(t.startswith("0 files  ·  0 B  ·  file on disk ") for t in texts)

    def test_a_wrong_password_is_reported_and_mounts_nothing(self, env, pw_volume):
        app, mp = self._ready(env, pw_volume)
        app._mount_pw_var.set("not the password")
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert app._mount_err.cget("text") == (
            "Couldn't mount: The password or shares are incorrect, or the file "
            "has been modified since it was encrypted.")
        assert env.mounted == {} and not os.path.exists(mp)
        assert app.focus_lastfor() is app._mount_pw_entry
        assert not app._mount_prog.winfo_ismapped()
        # A failed attempt keeps what was typed so it can be corrected.
        assert app._mount_pw_var.get() == "not the password"

    def test_mounting_a_split_key_volume_with_pasted_shares(self, env):
        path = str(env.tmp_path / "split.qcv")
        _meta, shares = vol.create_volume_shamir(path, 3, 2)
        app, mp = self._ready(env, path)
        assert app._mount_auth_var.get() == "shamir"
        app._mount_shares_text.insert("1.0", "\n".join(shares))
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert app._mount_status.cget("text") == f"✓ Mounted at {mp}"
        assert app._mount_shares_text.get("1.0", "end").strip() == ""
        assert env.mounted[mp]["volume_path"] == path

    def test_extra_shares_beyond_the_threshold_are_accepted(self, env):
        path = str(env.tmp_path / "split.qcv")
        _meta, shares = vol.create_volume_shamir(path, 3, 2)
        app, mp = self._ready(env, path)
        app._mount_shares_text.insert("1.0", "\n".join(shares))   # 3 for a 2-of-3
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert mp in env.mounted

    def test_too_few_shares_says_how_many_are_needed(self, env):
        path = str(env.tmp_path / "split.qcv")
        _meta, shares = vol.create_volume_shamir(path, 3, 2)
        app, mp = self._ready(env, path)
        app._mount_shares_text.insert("1.0", shares[0])
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert app._mount_err.cget("text") == \
            "Need 2 different shares to open this volume, got 1."
        assert env.mounted == {}

    def test_the_same_share_twice_does_not_count_twice(self, env):
        path = str(env.tmp_path / "split.qcv")
        _meta, shares = vol.create_volume_shamir(path, 3, 2)
        app, mp = self._ready(env, path)
        app._mount_shares_text.insert("1.0", shares[0] + "\n" + shares[0])
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert app._mount_err.cget("text") == \
            "Need 2 different shares to open this volume, got 1."

    def test_an_unparseable_share_is_named(self, env):
        path = str(env.tmp_path / "split.qcv")
        vol.create_volume_shamir(path, 3, 2)
        app, mp = self._ready(env, path)
        app._mount_shares_text.insert("1.0", "QCSHARE-not-a-real-code")
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert "Share 1" in app._mount_err.cget("text")
        assert env.mounted == {}
        # A share-shaped failure puts the keyboard back in the shares box —
        # the password entry is not even on screen in this mode.
        assert app.focus_lastfor() is app._mount_shares_text
        # The typed shares survive so the broken line can be corrected.
        assert app._mount_shares_text.get("1.0", "end").strip() == \
            "QCSHARE-not-a-real-code"

    def test_a_password_volume_with_the_split_key_toggle_dead_ends(
            self, env, pw_volume):
        """Documents current behaviour: the pre-flight check follows the
        toggle while the worker follows the volume's own mode.  Flipping the
        toggle to Split key on a password volume gets past the pre-flight and
        then asks for a password whose field is hidden.  Reported as a
        defect."""
        app, mp = self._ready(env, pw_volume)
        app._mount_auth_var.set("shamir")
        app.update()
        app._mount_shares_text.insert("1.0", _shares_2_of_3()[0])
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert app._mount_err.cget("text") == "Enter the password."
        assert not app._mount_pw_frame.winfo_ismapped()

    @pytest.mark.needs_real_window
    def test_a_permission_error_under_volumes_names_the_macos_rule(
            self, env, pw_volume, monkeypatch):
        monkeypatch.setattr(env.vm.sys, "platform", "darwin")
        app, _mp = self._ready(env, pw_volume)
        app._mount_point_var.set("/Volumes/vault")
        app._mount_pw_var.set(PW)
        env.mount_error = PermissionError(13, "denied", "/Volumes/vault")
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert app._mount_err.cget("text") == (
            "macOS doesn't let apps create folders in /Volumes. Use a folder in "
            "your home directory, e.g. ~/QuantaCrypt Volumes/vault.")
        assert app.focus_lastfor() is app._mount_point_entry

    @pytest.mark.needs_real_window
    def test_a_permission_error_elsewhere_points_at_the_folder(
            self, env, pw_volume, monkeypatch):
        monkeypatch.setattr(env.vm.sys, "platform", "linux")
        app, mp = self._ready(env, pw_volume)
        app._mount_pw_var.set(PW)
        env.mount_error = PermissionError(13, "denied", mp)
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert app._mount_err.cget("text") == (
            f"Couldn't create the mount point folder at {mp}: pick a folder "
            "you're allowed to write to.")
        assert app.focus_lastfor() is app._mount_point_entry

    def test_a_permission_error_about_the_volume_is_not_blamed_on_the_folder(
            self, env, pw_volume):
        app, mp = self._ready(env, pw_volume)
        app._mount_pw_var.set(PW)
        env.mount_error = PermissionError(13, "denied", pw_volume)
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert app._mount_err.cget("text") == (
            "Couldn't mount: Access denied. Check you have permission to "
            "read / write this file, and that it isn't open in another app.")

    def test_any_other_mount_failure_is_shown_verbatim(self, env, pw_volume):
        app, mp = self._ready(env, pw_volume)
        app._mount_pw_var.set(PW)
        env.mount_error = RuntimeError("Volume is already mounted at /elsewhere")
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert app._mount_err.cget("text") == \
            "Couldn't mount: Volume is already mounted at /elsewhere"

    def test_a_suspicious_journal_warns_instead_of_celebrating(self, env, pw_volume):
        env.mount_suspicious = True
        app, mp = self._ready(env, pw_volume)
        app._mount_pw_var.set(PW)
        env.reply(False)                       # "Keep mounted"
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert env.confirms == ["This volume may have been altered"]
        assert "vault.qcv" in env.confirm_msgs[-1]
        assert env.notifications == [], "no cheerful toast for a suspect volume"
        assert mp in env.mounted, "Keep mounted must leave it mounted"

    def test_unmount_now_on_a_suspicious_volume_unmounts_it(self, env, pw_volume):
        env.mount_suspicious = True
        app, mp = self._ready(env, pw_volume)
        app._mount_pw_var.set(PW)
        env.reply(True)                        # "Unmount now"
        app._do_mount()
        assert _pump_until(
            app, lambda: app._mount_status.cget("text").startswith("✓ Unmounted"))
        assert env.unmount_calls == [mp]
        assert env.confirms == ["This volume may have been altered"]
        assert mp not in env.mounted


# ── Unmounting ───────────────────────────────────────────────────────────────

@requires_tkinter
class TestUnmount:
    """Unmount runs off a worker so a busy ``diskutil`` cannot freeze the
    window; the row reports what happened either way."""

    def _mounted(self, env, pw_volume):
        app = env.make(volume_path=pw_volume)
        mp = str(env.tmp_path / "mnt")
        app._mount_point_var.set(mp)
        app._mount_pw_var.set(PW)
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        return app, mp

    def test_unmounting_confirms_then_empties_the_list(self, env, pw_volume):
        app, mp = self._mounted(env, pw_volume)
        env.reply(True)
        _button(app._mounted_list_frame, "Unmount")._fire()
        assert env.confirms == ["Unmount vault.qcv?"]
        assert _pump_until(
            app, lambda: app._mount_status.cget("text").startswith("✓ Unmounted"))
        assert env.unmount_calls == [mp]
        assert app._mount_status.cget("text") == "✓ Unmounted vault.qcv"
        assert "No volumes mounted. Unmounted vault.qcv." in \
            _widget_texts(app._mounted_list_frame)
        assert app._rows == {} and app._unmounting == set()

    def test_declining_leaves_the_volume_mounted(self, env, pw_volume):
        app, mp = self._mounted(env, pw_volume)
        env.reply(False)
        _button(app._mounted_list_frame, "Unmount")._fire()
        assert env.confirms == ["Unmount vault.qcv?"]
        assert env.unmount_calls == [] and mp in env.mounted
        assert app._unmounting == set()

    def test_a_second_click_is_ignored_while_the_first_is_running(
            self, env, pw_volume):
        app, mp = self._mounted(env, pw_volume)
        app._unmounting.add(mp)
        env.reply(True)
        app._do_unmount(mp)
        assert env.confirms == [] and env.unmount_calls == []
        # The in-flight set is the reason: drop it and the same call runs.
        app._unmounting.discard(mp)
        app._do_unmount(mp)
        assert env.confirms == ["Unmount vault.qcv?"]
        assert _pump_until(app, lambda: env.unmount_calls == [mp])

    def test_a_mount_point_the_registry_has_forgotten_is_named_by_its_folder(
            self, env):
        """The registry entry supplies the volume's filename; when the poll
        has already dropped the row (an external eject, a stale button) the
        question and the status line fall back to the mount point's own
        basename rather than showing an empty name."""
        app = env.make()
        app._mode_var.set("mount")
        app.update()
        env.reply(True)
        app._do_unmount("/tmp/gone volume")
        assert env.confirms == ["Unmount gone volume?"]
        assert _pump_until(
            app, lambda: app._mount_status.cget("text").startswith("✓ Unmounted"))
        assert env.unmount_calls == ["/tmp/gone volume"]
        assert app._mount_status.cget("text") == "✓ Unmounted gone volume"
        assert "No volumes mounted. Unmounted gone volume." in \
            _widget_texts(app._mounted_list_frame)

    def test_the_row_shows_that_it_is_unmounting(self, env, pw_volume):
        app, mp = self._mounted(env, pw_volume)
        row = app._rows[mp]
        app._set_row_busy(row, "Unmounting…")
        app.update()
        assert row["note"].cget("text") == "Unmounting…" and row["note"].winfo_ismapped()
        assert not any(b._enabled for b in row["buttons"])
        # A rebuild while the unmount is still running keeps the busy note.
        app._unmounting.add(mp)
        app._refresh_mounted_list(force=True)
        app.update()
        assert app._rows[mp]["note"].cget("text") == "Unmounting…"

    def test_a_failed_unmount_explains_and_keeps_the_row(self, env, pw_volume):
        app, mp = self._mounted(env, pw_volume)
        env.unmount_error = RuntimeError("Resource busy -- try again")
        env.reply(True)
        _button(app._mounted_list_frame, "Unmount")._fire()
        assert _pump_until(app, lambda: bool(env.alerts))
        assert [t for t, _ in env.alerts] == ["Couldn't unmount vault.qcv"]
        assert "Resource busy" in env.alerts[0][1]
        assert app._mount_status.cget("text") == "Couldn't unmount vault.qcv"
        assert "✗ Couldn't unmount. Something is still using it." in \
            _widget_texts(app._mounted_list_frame)
        assert mp in env.mounted
        assert app._unmounting == set(), "a retry must be possible"

    def test_reveal_opens_the_file_manager_at_the_mount_point(
            self, env, pw_volume, monkeypatch):
        from quantacrypt.ui.shared import REVEAL_LABEL
        opened = []
        monkeypatch.setattr(env.vm, "reveal_path",
                            lambda p: (opened.append(p), True)[1])
        app, mp = self._mounted(env, pw_volume)
        _button(app._mounted_list_frame, REVEAL_LABEL)._fire()
        app.update()
        assert opened == [mp]
        assert app._row_notes == {}
        assert not any("Couldn't open" in t
                       for t in _widget_texts(app._mounted_list_frame))

    def test_a_file_manager_that_will_not_open_says_where_the_volume_is(
            self, env, pw_volume, monkeypatch):
        from quantacrypt.ui.shared import REVEAL_LABEL
        app, mp = self._mounted(env, pw_volume)
        monkeypatch.setattr(env.vm, "reveal_path", lambda p: False)
        _button(app._mounted_list_frame, REVEAL_LABEL)._fire()
        app.update()
        assert f"Couldn't open the file manager. It's at {mp}" in \
            _widget_texts(app._mounted_list_frame)


# ── Mounted list ─────────────────────────────────────────────────────────────

@requires_tkinter
class TestMountedList:
    """The list is rebuilt only when the set of mounts changes, so hover and
    focus on its buttons survive the three-second poll."""

    def test_an_empty_list_says_so(self, env):
        app = env.make()
        app._mode_var.set("mount")
        app.update()
        assert "No volumes mounted." in _widget_texts(app._mounted_list_frame)
        assert app._rows == {}

    def test_statistics_are_the_containers_own(self, env, pw_volume):
        _hdr, auth = vol.read_volume_auth_params(pw_volume)
        vc = vol.VolumeContainer(pw_volume, vol.derive_volume_key_single(PW, auth))
        vc.open()
        vc.write_file("/a.txt", b"x" * 1000)
        vc.mkdir("/sub")
        vc.save()
        app = env.make()
        text = app._stats_text({"volume": vc})
        assert text.startswith("1 file  ·  1 folder  ·  1.0 KB  ·  file on disk ")

        vc.write_file("/b.txt", b"y" * 24)
        assert app._stats_text({"volume": vc}).startswith("2 files  ·  1 folder  ·  ")

    def test_statistics_degrade_gracefully(self, env):
        app = env.make()
        assert app._stats_text({}) == "", "a row with no container shows nothing"
        broken = SimpleNamespace(
            stat=lambda: (_ for _ in ()).throw(OSError("volume went away")))
        assert app._stats_text({"volume": broken}) == "Size unavailable"
        empty = SimpleNamespace(stat=lambda: {"file_count": 0, "dir_count": 0,
                                              "total_plaintext_size": 0,
                                              "container_size": 0})
        assert app._stats_text({"volume": empty}) == "0 files  ·  0 B"

    def test_several_mounts_each_get_their_own_row_and_buttons(
            self, env, pw_volume):
        """The many-case of the render loop: every mount needs its own name,
        path, statistics line and pair of buttons, and Unmount on one row
        must act on that row's mount point only."""
        app = env.make(volume_path=pw_volume)
        mp1 = str(env.tmp_path / "first mnt")
        app._mount_point_var.set(mp1)
        app._mount_pw_var.set(PW)
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)

        mp2 = str(env.tmp_path / "second mnt")
        env.mounted[mp2] = {"volume_path": str(env.tmp_path / "other.qcv"),
                            "volume": None}
        app._refresh_mounted_list(force=True)
        app.update()

        assert set(app._rows) == {mp1, mp2}
        texts = _widget_texts(app._mounted_list_frame)
        assert {"vault.qcv", "other.qcv", mp1, mp2} <= set(texts)
        assert len([b for b in _flat_buttons(app._mounted_list_frame)
                    if b.cget("text") == "Unmount"]) == 2
        # Only the real container has statistics; the placeholder row shows none.
        assert app._rows[mp1]["stats"].cget("text").startswith("0 files")
        assert app._rows[mp2]["stats"].cget("text") == ""

        env.reply(True)
        app._rows[mp2]["buttons"][1]._fire()          # the second row's Unmount
        assert env.confirms == ["Unmount other.qcv?"]
        assert _pump_until(app, lambda: set(app._rows) == {mp1})
        assert env.unmount_calls == [mp2]
        assert mp1 in env.mounted and mp2 not in env.mounted

    def test_an_unchanged_mount_set_refreshes_statistics_without_rebuilding(
            self, env, pw_volume):
        app = env.make(volume_path=pw_volume)
        mp = str(env.tmp_path / "mnt")
        app._mount_point_var.set(mp)
        app._mount_pw_var.set(PW)
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        row = app._rows[mp]
        app._render_mounted(dict(env.mounted), {mp: "brand new stats"})
        assert app._rows[mp] is row, "the widgets must survive so focus is not lost"
        assert row["stats"].cget("text") == "brand new stats"

    def test_a_mount_that_disappeared_externally_is_dropped(self, env, pw_volume):
        app = env.make(volume_path=pw_volume)
        mp = str(env.tmp_path / "mnt")
        app._mount_point_var.set(mp)
        app._mount_pw_var.set(PW)
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert set(app._rows) == {mp}
        env.mounted.clear()
        app._refresh_mounted_list()
        app.update()
        assert app._rows == {}
        assert "No volumes mounted." in _widget_texts(app._mounted_list_frame)

    def test_the_poll_renders_new_mounts_and_re_arms_itself(self, env, pw_volume):
        app = env.make()
        app._mode_var.set("mount")
        app.update()
        app._cancel_jobs()
        env.mounted["/tmp/elsewhere"] = {"volume_path": "/tmp/other.qcv",
                                         "volume": None}
        app._poll_mounted()
        assert _pump_until(app, lambda: app._refresh_job is not None)
        assert set(app._rows) == {"/tmp/elsewhere"}
        assert "other.qcv" in _widget_texts(app._mounted_list_frame)

    def test_a_poll_that_cannot_read_the_registry_still_re_arms(self, env):
        """get_mounted_volumes takes the mount lock that an unmount holds
        across ``diskutil``; a poll that loses that race must keep polling."""
        app = env.make()
        app._cancel_jobs()
        env.mounted_error = RuntimeError("lock held")
        app._poll_mounted()
        assert _pump_until(app, lambda: app._refresh_job is not None)
        assert app._rows == {}

    def test_a_poll_whose_rendering_fails_keeps_polling(self, env):
        """The snapshot hops back to the main thread a moment later, by which
        time the list frame may be gone.  Rendering into it raises, and the
        poll still has to re-arm — otherwise one bad frame silently ends the
        three-second refresh for the life of the window."""
        import tkinter as tk
        app = env.make()
        app._mode_var.set("mount")
        app.update()
        app._cancel_jobs()
        env.mounted["/tmp/elsewhere"] = {"volume_path": "/tmp/other.qcv",
                                         "volume": None}
        app._mounted_list_frame.destroy()

        app._poll_mounted()
        assert _pump_until(app, lambda: app._refresh_job is not None), \
            "a failed render must not stop the poll"
        # It really did try and really did fail: the key was taken before the
        # frame was touched, and no row survived the attempt.
        assert app._last_mounted_key == ("/tmp/elsewhere",)
        assert app._rows == {}
        with pytest.raises(tk.TclError):
            app._render_mounted(dict(env.mounted), {}, force=True)

    def test_the_poll_stops_once_the_window_is_gone(self, env, monkeypatch):
        """``_refresh_job`` is already None once the jobs are cancelled, so
        asserting only that would pass for a poll that did nothing at all.
        The observable difference is the registry read the worker performs:
        a live window takes a snapshot, a destroyed one takes none."""
        reads = []

        def _counted():
            reads.append(1)
            return dict(env.mounted)

        app = env.make()
        app._cancel_jobs()
        monkeypatch.setattr(env.fo, "get_mounted_volumes", _counted)
        app._poll_mounted()
        assert _pump_until(app, lambda: app._refresh_job is not None)
        assert reads == [1], "a live window polls the registry and re-arms"

        app._cancel_jobs()
        app.destroy()
        app._poll_mounted()
        time.sleep(0.25)        # ample for a worker thread, had one started
        assert reads == [1], "a dead window must not read the mount registry"
        assert app._refresh_job is None


# ── Remaining branches ───────────────────────────────────────────────────────

@requires_tkinter
class TestSecondRun:
    """A second creation in the same window must not inherit the first run's
    progress bar (it would still show "Complete" and the wrong stage list)."""

    def test_the_previous_progress_bar_is_replaced(self, env):
        app = env.make()
        app._loc_var.set(str(env.tmp_path / "first.qcv"))
        _set_password(app, PW)
        env.reply(False)
        app._do_create()
        assert _pump_until(app, lambda: not app._busy)
        first_bar = app._progress
        assert first_bar._stage_lbl.cget("text") == "Complete"

        app._loc_var.set(str(env.tmp_path / "second.qcv"))
        _set_password(app, PW)
        env.reply(False)
        app._do_create()
        assert app._progress is not first_bar
        assert not first_bar.winfo_exists(), "the stale bar must be destroyed"
        assert _pump_until(app, lambda: not app._busy)
        assert (env.tmp_path / "first.qcv").exists()
        assert (env.tmp_path / "second.qcv").exists()


@requires_tkinter
class TestTickerEdges:
    """The elapsed-seconds ticker re-arms itself every second, so it has to
    notice when the thing it is counting for has gone."""

    def test_a_tick_after_the_ticker_was_dropped_stops_quietly(self, env):
        app = _setup_app(env)
        app._start_ticker("fusepy", "Installing…")
        label = app._comp_widgets["fusepy"]["detail_lbl"]
        assert label.cget("text") == "Installing… 0s"
        # Drop the entry without cancelling its pending job — the shape of a
        # stop that raced the timer.
        app._tickers.clear()
        _pump_until(app, lambda: False, 1.3)
        assert label.cget("text") == "Installing… 0s", "the loop must not re-arm"

    def test_a_ticker_for_a_row_that_does_not_exist_does_not_re_arm(self, env):
        """``_start_ticker`` is reachable before the setup screen is built
        (there are no component rows on a working system)."""
        app = env.make()
        assert not hasattr(app, "_comp_widgets")
        app._start_ticker("fuse_backend", "Installing…")
        assert app._tickers["fuse_backend"]["job"] is None


@requires_tkinter
class TestRecheckClearsExtraButtons:
    """The "Open in Terminal" button is added to the backend row on demand;
    a successful recheck has to take it away with the rest of the row's
    install controls."""

    def test_the_terminal_button_disappears_once_the_backend_is_found(
            self, env, monkeypatch):
        monkeypatch.setattr(env.vm.sys, "platform", "darwin")
        monkeypatch.setattr(env.vm.shutil, "which", lambda name: "/opt/homebrew/bin/brew")
        app = _setup_app(env)
        _button(app._setup_frame, "How to install…")._fire()
        app.update()
        term = _button(app._setup_frame, "Open in Terminal")
        assert term.winfo_ismapped()

        env.components = dict(_Env.OK_COMPONENTS)
        _button(app._setup_frame, "Check again")._fire()
        app.update()
        assert not term.winfo_ismapped()
        assert not app._comp_widgets["fuse_backend"]["cmd_box"].winfo_ismapped()
        assert app._fuse_ok


@requires_tkinter
class TestUnlockModeMismatch:
    """The pre-flight check follows the unlock toggle, the worker follows the
    volume's own auth params.  Both mismatches must end in a message rather
    than a wrong-key crash."""

    def test_a_split_key_volume_with_the_password_toggle_asks_for_shares(self, env):
        path = str(env.tmp_path / "split.qcv")
        vol.create_volume_shamir(path, 3, 2)
        app = env.make(volume_path=path)
        app._mount_point_var.set(str(env.tmp_path / "mnt"))
        assert app._mount_auth_var.get() == "shamir"
        app._mount_auth_var.set("password")          # user overrides the detection
        app.update()
        app._mount_pw_var.set("a password this volume never had")
        app._do_mount()
        assert _pump_until(app, lambda: not app._busy)
        assert app._mount_err.cget("text") == "Paste your recovery shares."
        assert env.mount_calls == [] and env.mounted == {}
