#!/usr/bin/env python3
"""QuantaCrypt Volume Manager — create, mount, and unmount encrypted volumes."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Callable

from quantacrypt.core import crypto as cc
from quantacrypt.core import package as pkg
from quantacrypt.core import volume as vol
from quantacrypt.core.crypto import CancelledOperation
from quantacrypt.ui.shared import (
    C, F, SP, ICON, REVEAL_LABEL,
    styled_entry, bind_context_menu, bind_shortcut, fmt_size, rule,
    section_label, card, friendly_error, confirm, alert, reveal_path,
    safe_after, write_new_private_file,
    FlatButton, SegmentedControl, StagedProgressBar,
    PasswordStrengthBar, ClipboardTimer, RecentVolumes,
    notify,
)

_RELEASES_URL = "https://github.com/alexboccard/QuantaCrypt/releases"
_FUSE_T_URL = "https://www.fuse-t.org/"
_MACFUSE_URL = "https://macfuse.github.io/"


# ── Volume Creation Stages ──────────────────────────────────────────────────
# One stage list per protection mode: Shamir creation never derives a
# password key, so it must not show "Securing password".  Keyword lists are
# ordered most-specific first so "Encrypting Kyber private key" is not
# swallowed by the plain "kyber" match.

STAGES_PASSWORD = [
    ("Securing password", 0.60),
    ("Generating keys",   0.20),
    ("Writing volume",    0.20),
]
_KW_PASSWORD = [
    ("argon2", 0),
    ("private key", 2), ("writing", 2), ("created", 2),
    ("kyber", 1), ("encapsulat", 1),
]

STAGES_SHAMIR = [
    ("Generating keys", 0.50),
    ("Splitting key",   0.20),
    ("Writing volume",  0.30),
]
_KW_SHAMIR = [
    ("private key", 1),
    ("writing", 2), ("created", 2),
    ("master key", 0), ("kyber", 0), ("encapsulat", 0),
]

STAGES = STAGES_PASSWORD  # backward-compatible alias

_MOUNT_STAGES = [
    ("Reading volume", 0.10),
    ("Unlocking",      0.70),
    ("Mounting",       0.20),
]


def _find_stage(msg: str, stages: list | None = None):
    """Map a core progress message to ``(stage_index, friendly_label)``.

    The friendly ``STAGES`` name is what the bar shows; an ``NN%`` suffix
    from the core (if any) is kept so the bar can interpolate within the stage.
    """
    stages = stages or STAGES_PASSWORD
    keywords = _KW_SHAMIR if stages is STAGES_SHAMIR else _KW_PASSWORD
    low = msg.lower()
    for kw, idx in keywords:
        if kw in low:
            name = stages[idx][0]
            m = re.search(r"(\d+)%", msg)
            if m:
                name = f"{name} {m.group(1)}%"
            return idx, name
    return None, None


_MAX_SHARE_FILE = 1 << 20   # share .txt files are a few KB; refuse anything huge


def _parse_share_text(text: str) -> list[str]:
    """Free text from the mount panel → one entry per share, ready for
    pkg.normalize_shares.

    The tolerant parse is core's ``extract_share_codes`` (shared with the
    decryptor and qc-core): QCSHARE- lines are taken as-is and 50-word
    phrases are gathered only from lines made of BIP-39 words, so headers
    and prose — this screen's own "Save all shares…" file, the encryptor's
    ``.share-N-of-M.txt`` — paste cleanly instead of being swallowed into a
    bogus "mnemonic".  A QCSHARE- line that does not decode is kept verbatim
    (in place) so normalize_shares can name the typo rather than silently
    dropping it."""
    entries: list[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.upper().startswith("QCSHARE-"):
            try:
                entries.append(cc.encode_share(cc.decode_share(line)))
            except Exception:
                entries.append(line)
    for code in pkg.extract_share_codes(text):
        if code not in entries:
            entries.append(code)   # from a 50-word phrase
    return entries


def _blames_mount_point(exc: PermissionError, mount_point: str) -> bool:
    """True when the PermissionError is about the mount point (or a parent
    of it) rather than, say, an unreadable .qcv file.  Unknown → True so
    the mount-point advice stays the default for os.makedirs failures."""
    fn = getattr(exc, "filename", None)
    if not fn:
        return True
    fn_abs = os.path.abspath(str(fn))
    mp_abs = os.path.abspath(mount_point)
    return fn_abs == mp_abs or mp_abs.startswith(fn_abs.rstrip(os.sep) + os.sep)


# ── Volume Manager Window ────────────────────────────────────────────────────

class VolumeManagerApp(tk.Toplevel):
    """Combined volume creation wizard and mount/unmount panel."""

    _P = SP["xl"]            # outer padding, one value for every panel
    _STATUS_TTL_MS = 8000    # how long a top-level status line stays visible
    _REFRESH_MS = 3000       # mounted-list poll interval while the window lives
    _WRAP = 440

    def __init__(self, master: tk.Misc, on_close: Callable | None = None,
                 center_at: tuple[int, int] | None = None,
                 volume_path: str | None = None):
        super().__init__(master)
        self.title("QuantaCrypt — Encrypted Volumes")
        self.configure(bg=C["bg"])
        self.resizable(False, True)

        self._on_close = on_close
        self._center_at = center_at
        self._mode_var = tk.StringVar(value="mount" if volume_path else "create")

        self._busy = False               # a create/mount worker is running
        self._busy_what = ""
        self._cancel_event = threading.Event()
        self._auto_mp = ""               # last auto-filled mount point (Q25)
        self._unmounting: set[str] = set()
        self._row_notes: dict[str, tuple[str, str]] = {}   # mp → (text, fg)
        self._rows: dict[str, dict] = {}
        self._last_mounted_key: tuple | None = None
        self._refresh_job = None
        self._focus_job = None
        self._status_job = None
        self._tickers: dict[str, dict] = {}
        self._empty_note = ""
        # Split-key shares of the volume just created — held here (not in a
        # dialog local) until the user has saved them and dismissed the dialog.
        self._pending_shares: list[str] | None = None

        self._build()
        self._center()

        # Prefill the mount panel: an explicit path wins, else the most
        # recently mounted volume (M25).
        if volume_path:
            self._mount_path_var.set(volume_path)
            self._on_volume_selected(show_errors=True)
        else:
            recent = RecentVolumes.load()
            if recent:
                self._mount_path_var.set(recent[0][0])

        self.protocol("WM_DELETE_WINDOW", self._close)
        self.bind("<Escape>", lambda e: self._close())
        bind_shortcut(self, "n", lambda: self._mode_var.set("create"))
        bind_shortcut(self, "m", lambda: self._mode_var.set("mount"))
        # Tracked, not fire-and-forget: _cancel_jobs() cancels every other
        # timer in this class, and an untracked one outlives the window it
        # was scheduled from — it then moves the keyboard focus of whatever
        # window exists 50 ms later.
        self._focus_job = self.after(50, self._focus_first)
        self._schedule_refresh()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def commit_quit(self) -> None:
        """State changes deferred out of ``can_quit()`` until the quit is
        certain: cancel a running worker so it tears its partial file down."""
        if self._busy:
            self._cancel_event.set()

    def _close(self):
        if not self.can_quit():
            return
        self.commit_quit()
        self._cancel_jobs()
        self.destroy()
        if self._on_close:
            self._on_close()

    def can_quit(self) -> bool:
        """Whether this window consents to closing — a pure predicate that
        changes no state, so a later window's veto (``_register_quit`` asks
        every window, then the launcher) cannot leave a job already
        cancelled behind a quit that did not happen (review run 20 F-005).
        The cancel is taken in ``commit_quit()`` once the quit is certain."""
        if self._busy:
            if self._busy_what == "create":
                return confirm(
                    self, "Creation is still running",
                    "Quitting now abandons it. A partial, unusable volume file "
                    "may be left in the destination folder; delete it by hand.",
                    yes="Abandon and quit", no="Keep working", danger=True)
            return confirm(
                self, "Mounting is still running",
                "A mount can't be interrupted. Quitting now abandons it; if it "
                "had already succeeded the drive stays mounted until you eject "
                "it in Finder.",
                yes="Quit anyway", no="Keep working", danger=True)
        if self._pending_shares:
            # The shares dialog is up (or was reached around) — these are
            # the only way the new volume will ever open.
            if not confirm(self, "Shares not saved",
                           "The recovery shares of the volume you just created "
                           "haven't been saved. Closing this window throws them "
                           "away and the volume can never be opened.",
                           yes="Discard shares", no="Go back", danger=True):
                return False
        if self._has_typed_input():
            if not confirm(self, "Discard what you typed?",
                           "Your password or shares haven't been used yet. "
                           "Closing this window throws them away.",
                           yes="Discard", no="Keep editing", danger=True):
                return False
        return True

    def _has_typed_input(self) -> bool:
        """A password or shares typed on either panel and not yet used."""
        for var in ("_pw_var", "_pw2_var", "_mount_pw_var"):
            try:
                if getattr(self, var).get():
                    return True
            except Exception:
                pass
        try:
            return bool(self._mount_shares_text.get("1.0", "end").strip())
        except Exception:
            return False

    def _cancel_jobs(self):
        for job in (self._refresh_job, self._status_job,
                    getattr(self, "_focus_job", None)):
            if job is not None:
                try:
                    self.after_cancel(job)
                except Exception:
                    pass
        self._refresh_job = self._status_job = self._focus_job = None
        for key in list(self._tickers):
            self._stop_ticker(key)

    def _after(self, fn, delay: int = 0):
        """``after()`` that tolerates a window the worker has outlived."""
        safe_after(self, fn, delay)

    def _center(self):
        self.update_idletasks()
        if self._center_at:
            cx, cy = self._center_at
            w, h = self.winfo_width(), self.winfo_height()
            self.geometry(f"+{cx - w // 2}+{cy - h // 2}")
        else:
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            w, h = self.winfo_width(), self.winfo_height()
            self.geometry(f"+{(sw - w) // 2}+{(sh - h) // 2}")

    # ── Layout ───────────────────────────────────────────────────────────────

    def _build(self):
        P = self._P

        # ── Header ──
        hdr = tk.Frame(self, bg=C["bg"])
        hdr.pack(fill="x", padx=P, pady=(P, 0))
        tk.Label(hdr, text="Encrypted Volumes", font=F["display"],
                 bg=C["bg"], fg=C["text"]).pack(side="left")
        FlatButton(hdr, f"{ICON['back']} Home", self._close,
                   primary=False, small=True).pack(side="right")
        tk.Label(self, text="Create or mount encrypted virtual drives",
                 font=F["body"], bg=C["bg"], fg=C["text3"]).pack(
            anchor="w", padx=P, pady=(SP["xs"], 0))

        rule(self, pady=SP["l"], padx=P)

        # ── Mode toggle ──
        seg_frame = tk.Frame(self, bg=C["bg"])
        seg_frame.pack(padx=P, fill="x")
        SegmentedControl(seg_frame,
                         [("create", "Create New"), ("mount", "Mount Existing")],
                         self._mode_var).pack(fill="x")
        self._mode_var.trace_add("write", lambda *_: self._on_mode_change())

        # One FUSE check feeds both panels: the create panel's warning strip
        # (Q29) and the mount panel's setup screen.
        from quantacrypt.core.fuse_ops import check_fuse_components
        self._components = check_fuse_components()
        self._fuse_ok = all(c["ok"] for c in self._components.values())

        # ── Content frames ──
        self._create_frame = tk.Frame(self, bg=C["bg"])
        self._mount_frame = tk.Frame(self, bg=C["bg"])
        self._build_create_panel(self._create_frame)
        self._build_mount_panel(self._mount_frame)
        self._show_panel()

    def _show_panel(self):
        P = self._P
        self._create_frame.pack_forget()
        self._mount_frame.pack_forget()
        frame = self._create_frame if self._mode_var.get() == "create" else self._mount_frame
        frame.pack(fill="both", expand=True, padx=P, pady=(SP["m"], P))

    def _on_mode_change(self):
        self._show_panel()
        self._focus_first()

    def _focus_first(self):
        """Put the keyboard somewhere useful on open and after a panel switch."""
        try:
            if self._mode_var.get() == "create":
                self._loc_entry.focus_set()
            elif self._setup_frame is not None and self._setup_frame.winfo_ismapped():
                self._recheck_btn.focus_set()
            elif not self._mount_path_var.get().strip():
                self._mount_path_entry.focus_set()
            elif self._mount_auth_var.get() == "password":
                self._mount_pw_entry.focus_set()
            else:
                self._mount_shares_text.focus_set()
        except Exception:
            pass

    @staticmethod
    def _toggle_show(entry: tk.Entry, btn: FlatButton):
        hidden = entry.cget("show") != ""
        entry.config(show="" if hidden else "•")
        btn.set_text("Hide" if hidden else "Show")

    def _set_status(self, text: str, fg: str | None = None, *, expire: bool = True):
        """Top-level mount status.  Expires after ``_STATUS_TTL_MS`` so a
        stale 'Mounted at …' never outlives the mount."""
        if self._status_job is not None:
            try:
                self.after_cancel(self._status_job)
            except Exception:
                pass
            self._status_job = None
        self._mount_status.config(text=text, fg=fg or C["text3"])
        if text and expire:
            self._status_job = self.after(
                self._STATUS_TTL_MS, lambda: self._mount_status.config(text=""))

    # ── Create Panel ─────────────────────────────────────────────────────────

    def _build_create_panel(self, parent: tk.Frame):
        # Protection mode
        self._auth_var = tk.StringVar(value="password")
        tk.Label(parent, text="Protection", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w", pady=(SP["s"], 0))
        SegmentedControl(parent,
                         [("password", "Password"), ("shamir", "Split key")],
                         self._auth_var).pack(fill="x", pady=(SP["xs"], 0))
        self._auth_var.trace_add("write", lambda *_: self._on_auth_change())

        # FUSE warning strip (Q29) — shown only while a component is missing
        self._fuse_warn = card(parent, padx=SP["m"], pady=SP["s"])
        wrow = tk.Frame(self._fuse_warn, bg=C["surface"])
        wrow.pack(fill="x")
        tk.Label(wrow, text=f"{ICON['warn']}  Mounting needs disk-mounting support. "
                            "set it up under Mount Existing.",
                 font=F["caption"], bg=C["surface"], fg=C["warning"],
                 wraplength=340, justify="left").pack(side="left", fill="x", expand=True)
        FlatButton(wrow, f"Set up {ICON['arrow']}",
                   lambda: self._mode_var.set("mount"),
                   primary=False, small=True).pack(side="right", padx=(SP["s"], 0))
        if not self._fuse_ok:
            self._fuse_warn.outer.pack(fill="x", pady=(SP["m"], 0))

        # Location
        tk.Label(parent, text="Save volume as", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w", pady=(SP["l"], 0))
        row = tk.Frame(parent, bg=C["bg"])
        row.pack(fill="x", pady=(SP["xs"], 0))
        self._loc_var = tk.StringVar()
        self._loc_entry = styled_entry(row, textvariable=self._loc_var)
        self._loc_entry.pack(side="left", fill="x", expand=True)
        self._loc_entry.bind("<Return>", lambda e: self._do_create())
        FlatButton(row, "Browse…", self._browse_save_location,
                   primary=False, small=True).pack(side="left", padx=(SP["s"], 0))
        tk.Label(parent, text="One .qcv file holds everything. The volume grows "
                              "as you add files, so there's no fixed size to choose.",
                 font=F["caption"], bg=C["bg"], fg=C["text3"],
                 wraplength=self._WRAP, justify="left").pack(anchor="w", pady=(SP["xs"], 0))

        # Credentials slot — holds either the password or the split-key fields
        self._cred_slot = tk.Frame(parent, bg=C["bg"])
        self._cred_slot.pack(fill="x", pady=(SP["l"], 0))

        # Password fields (password mode)
        self._pw_frame = tk.Frame(self._cred_slot, bg=C["bg"])
        self._pw_frame.pack(fill="x")
        tk.Label(self._pw_frame, text="Password", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w")
        pw_row = tk.Frame(self._pw_frame, bg=C["bg"])
        pw_row.pack(fill="x", pady=(SP["xs"], 0))
        self._pw_var = tk.StringVar()
        self._pw_entry = styled_entry(pw_row, textvariable=self._pw_var, show="•")
        self._pw_entry.pack(side="left", fill="x", expand=True)
        self._pw_show = FlatButton(
            pw_row, "Show", lambda: self._toggle_show(self._pw_entry, self._pw_show),
            primary=False, small=True)
        self._pw_show.pack(side="left", padx=(SP["s"], 0))
        self._pw_strength = PasswordStrengthBar(self._pw_frame, self._pw_var)
        self._pw_strength.pack(fill="x", pady=(SP["xs"], 0))

        tk.Label(self._pw_frame, text="Confirm password", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w", pady=(SP["s"], 0))
        pw2_row = tk.Frame(self._pw_frame, bg=C["bg"])
        pw2_row.pack(fill="x", pady=(SP["xs"], 0))
        self._pw2_var = tk.StringVar()
        self._pw2_entry = styled_entry(pw2_row, textvariable=self._pw2_var, show="•")
        self._pw2_entry.pack(side="left", fill="x", expand=True)
        self._pw2_show = FlatButton(
            pw2_row, "Show", lambda: self._toggle_show(self._pw2_entry, self._pw2_show),
            primary=False, small=True)
        self._pw2_show.pack(side="left", padx=(SP["s"], 0))
        self._pw_entry.bind("<Return>", lambda e: self._pw2_entry.focus_set())
        self._pw2_entry.bind("<Return>", lambda e: self._do_create())

        # Split-key fields (hidden by default)
        self._shamir_frame = tk.Frame(self._cred_slot, bg=C["bg"])
        srow = tk.Frame(self._shamir_frame, bg=C["bg"])
        srow.pack(fill="x")
        ncol = tk.Frame(srow, bg=C["bg"])
        ncol.pack(side="left", padx=(0, SP["xl"]))
        tk.Label(ncol, text="Total shares", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w")
        self._n_var = tk.StringVar(value="3")
        self._n_entry = styled_entry(ncol, textvariable=self._n_var, width=6)
        self._n_entry.pack(anchor="w", pady=(SP["xs"], 0))
        kcol = tk.Frame(srow, bg=C["bg"])
        kcol.pack(side="left")
        tk.Label(kcol, text="Required to unlock", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w")
        self._k_var = tk.StringVar(value="2")
        self._k_entry = styled_entry(kcol, textvariable=self._k_var, width=6)
        self._k_entry.pack(anchor="w", pady=(SP["xs"], 0))
        self._n_entry.bind("<Return>", lambda e: self._k_entry.focus_set())
        self._k_entry.bind("<Return>", lambda e: self._do_create())
        tk.Label(self._shamir_frame,
                 text="Split key: you choose how many shares are needed to unlock the "
                      "volume. There is "
                      "no password; you get the shares right after creation.",
                 font=F["caption"], bg=C["bg"], fg=C["text3"],
                 wraplength=self._WRAP, justify="left").pack(anchor="w", pady=(SP["s"], 0))

        # Progress row: bar + Cancel (bar is built per run — the stage list
        # depends on the protection mode)
        self._prog_row = tk.Frame(parent, bg=C["bg"])
        self._progress: StagedProgressBar | None = None
        self._cancel_btn = FlatButton(self._prog_row, "Cancel", self._request_cancel,
                                      primary=False, small=True)

        # Create button + inline error (M23)
        self._create_btn = FlatButton(parent, f"Create volume {ICON['arrow']}",
                                      self._do_create)
        self._create_btn.pack(fill="x", pady=(SP["l"], 0))
        self._err = tk.Label(parent, text="", font=F["caption"], bg=C["bg"],
                             fg=C["error"], anchor="w", justify="left",
                             wraplength=self._WRAP)
        self._err.pack(fill="x", pady=(SP["s"], 0))

    def _on_auth_change(self):
        if self._auth_var.get() == "password":
            self._shamir_frame.pack_forget()
            self._pw_frame.pack(fill="x")
            self._after(self._pw_entry.focus_set)
        else:
            self._pw_frame.pack_forget()
            self._shamir_frame.pack(fill="x")
            self._after(self._n_entry.focus_set)

    def _browse_save_location(self):
        p = filedialog.asksaveasfilename(
            title="Save encrypted volume",
            defaultextension=".qcv",
            filetypes=[("QuantaCrypt Volume", "*.qcv"), ("All files", "*")],
            initialdir=os.path.expanduser("~"),
            parent=self,
        )
        if p:
            self._loc_var.set(p)

    def _fail_create(self, msg: str, focus: tk.Widget | None = None):
        self._err.config(text=msg, fg=C["error"])
        if focus is not None:
            focus.focus_set()

    def _do_create(self):
        if self._busy:
            return
        self._err.config(text="")
        path = os.path.expanduser(self._loc_var.get().strip())
        if not path:
            self._fail_create("Choose where to save the volume.", self._loc_entry)
            return
        if not path.lower().endswith(".qcv"):
            path += ".qcv"
            self._loc_var.set(path)

        # Credentials first (Q32) — never ask "overwrite?" for a form that
        # is about to be rejected anyway.
        auth = self._auth_var.get()
        pw = ""
        n = k = 0
        if auth == "password":
            pw, pw2 = self._pw_var.get(), self._pw2_var.get()
            if not pw:
                self._fail_create("Enter a password.", self._pw_entry)
                return
            # Same floor as the core, checked before the weak-password
            # dialog: otherwise "Use it anyway" leads to a guaranteed failure.
            if len(pw) < cc.MIN_PASSWORD_LENGTH:
                self._fail_create(
                    f"Use at least {cc.MIN_PASSWORD_LENGTH} characters.",
                    self._pw_entry)
                return
            if pw != pw2:
                self._fail_create("The two passwords don't match.", self._pw2_entry)
                return
            # Scored on the strength bar's worker thread as the user typed —
            # reuse that instead of freezing the window on Create.
            score = self._pw_strength.score_for(pw)
            if score < 2 and not confirm(
                    self, "Weak password",
                    "This password is rated Weak and could be guessed. A longer "
                    "password mixing words, numbers and symbols is safer.\n\n"
                    "Use it anyway?",
                    yes="Use it anyway", no="Choose another", danger=True):
                self._pw_entry.focus_set()
                return
        else:
            try:
                n = int(self._n_var.get().strip())
                k = int(self._k_var.get().strip())
            except ValueError:
                self._fail_create("Enter whole numbers for total shares and "
                                  "required shares.", self._n_entry)
                return
            if n < 2 or n > 20:
                self._fail_create("Total shares must be between 2 and 20.", self._n_entry)
                return
            if k < 2 or k > n:
                self._fail_create(f"Required shares must be between 2 and {n}.",
                                  self._k_entry)
                return

        # create_volume_* opens the path with "wb" — immediate truncation.
        # The Browse dialog confirms overwrites, but a typed path gets no
        # check, and neither path knows about live mounts.
        try:
            from quantacrypt.core.fuse_ops import get_mounted_volumes
            real = os.path.realpath(path)
            for mp, info in get_mounted_volumes().items():
                if os.path.realpath(info.get("volume_path", "")) == real:
                    alert(self, "Volume is mounted",
                          f"That volume is currently mounted at {mp}.\n\n"
                          "Creating over a mounted volume would destroy it. "
                          "Unmount it first.")
                    return
        except Exception:
            pass  # fuse_ops unavailable → nothing can be mounted
        existed = os.path.exists(path)
        if existed:
            # The in-process check above can't see another app instance or
            # a script: probe the cross-process mount flock too (acquired
            # and immediately released — creation itself is guarded by the
            # overwrite prompt below).
            try:
                from quantacrypt.core.fuse_ops import _acquire_volume_lock
                probe_fd = _acquire_volume_lock(path)
                os.close(probe_fd)
            except RuntimeError:
                alert(self, "Volume is mounted",
                      "That volume appears to be mounted by another "
                      "QuantaCrypt process.\n\n"
                      "Creating over a mounted volume would destroy it. "
                      "Unmount it there first.")
                return
            except Exception:
                pass  # probe unavailable → fall through to the prompt
            if not confirm(self, "Overwrite volume?",
                           f"{os.path.basename(path)} already exists. Creating a new "
                           "volume here will PERMANENTLY destroy the existing one. "
                           "its contents cannot be recovered.\n\nOverwrite it?",
                           yes="Overwrite", no="Cancel", danger=True):
                return

        # Freeze the form, show the progress row
        stages = STAGES_PASSWORD if auth == "password" else STAGES_SHAMIR
        self._busy = True
        self._busy_what = "create"
        self._cancel_event.clear()
        self._create_btn.enable(False)
        if self._progress is not None:
            self._progress.destroy()
        self._progress = StagedProgressBar(self._prog_row, stages)
        self._cancel_btn.pack(side="right", padx=(SP["s"], 0), anchor="n")
        self._cancel_btn.enable(True)
        self._progress.pack(side="left", fill="x", expand=True)
        self._prog_row.pack(fill="x", pady=(SP["m"], 0), before=self._create_btn)
        self._progress.start()
        self._cancel_btn.focus_set()
        started = time.time()

        def _discard_partial():
            # Only remove what THIS run wrote: a pre-existing file that was
            # never truncated (cancel during the KDF) must survive.
            try:
                if not existed or os.path.getmtime(path) >= started:
                    os.remove(path)
            except OSError:
                pass

        def _worker():
            # cancel_check lets the core stop BEFORE the file is opened: a
            # cancel during the KDF (the long part) leaves a pre-existing
            # volume the user agreed to overwrite untouched.
            cancel_check = self._cancel_event.is_set
            try:
                if auth == "password":
                    meta = vol.create_volume_single(
                        path, pw, progress_cb=_progress, cancel_check=cancel_check)
                    shares = None
                else:
                    meta, shares = vol.create_volume_shamir(
                        path, n, k, progress_cb=_progress, cancel_check=cancel_check)
            except CancelledOperation:
                _discard_partial()
                self._after(self._on_create_cancelled)
                return
            except Exception as e:
                if self._cancel_event.is_set():
                    _discard_partial()
                    self._after(self._on_create_cancelled)
                else:
                    self._after(lambda exc=e: self._on_create_error(exc))
                return
            if self._cancel_event.is_set():
                _discard_partial()
                self._after(self._on_create_cancelled)
                return
            self._after(lambda: self._on_create_done(path, meta, shares=shares))

        def _progress(msg):
            idx, label = _find_stage(msg, stages)
            if idx is not None:
                self._after(lambda: self._progress.advance(idx, label))

        threading.Thread(target=_worker, daemon=True).start()

    def _request_cancel(self):
        """Flag the worker: the core checks ``cancel_check`` between stages
        and raises CancelledOperation, then whatever THIS run wrote is
        deleted (a not-yet-truncated existing volume survives)."""
        if not self._busy or self._busy_what != "create":
            return
        self._cancel_event.set()
        self._cancel_btn.enable(False)
        self._err.config(text="Cancelling. Finishing the current step, then "
                              "deleting the unfinished volume…", fg=C["text3"])

    def _end_create_busy(self):
        self._busy = False
        self._busy_what = ""
        self._prog_row.pack_forget()
        self._create_btn.enable(True)

    def _on_create_cancelled(self):
        if self._progress is not None:
            self._progress.stop()
        self._end_create_busy()
        self._err.config(text="Creation cancelled. Nothing was kept.", fg=C["text3"])
        self._loc_entry.focus_set()

    def _on_create_done(self, path: str, meta: dict, shares: list | None = None):
        if self._progress is not None:
            self._progress.complete()
        self._end_create_busy()
        self._pw_var.set("")
        self._pw2_var.set("")
        name = os.path.basename(path)
        notify("Volume Created", f"Encrypted volume saved to {name}")
        RecentVolumes.add(path, meta)

        if shares:
            self._show_shares_dialog(shares, meta)
            if not self.winfo_exists():
                return   # the manager was closed while the dialog was up

        # Q31: offer to mount it right here instead of pointing at a "tab"
        self._err.config(text=f"{ICON['ok']} Created {name}", fg=C["success"])
        if confirm(self, "Volume created",
                   f"{name} is ready.\n\nMount it now?",
                   yes="Mount now", no="Later", default_no=False):
            self._mount_path_var.set(path)
            self._mount_pw_var.set("")
            self._mode_var.set("mount")

    def _on_create_error(self, err):
        if self._progress is not None:
            self._progress.stop()
        self._end_create_busy()
        # Accept either an exception or a raw string; translate to a
        # user-friendly message before displaying.
        msg = friendly_error(err) if isinstance(err, BaseException) else str(err)
        self._err.config(text=f"Couldn't create the volume: {msg}", fg=C["error"])
        self._loc_entry.focus_set()

    def _show_shares_dialog(self, shares: list[str], meta: dict):
        """Modal 'save your shares' screen (M21): per-share Copy with the
        clipboard countdown, Save all shares… to a fresh 0600 file.  The
        shares stay on ``self`` until the dialog is dismissed, and leaving
        without a save — Escape, the close box or the primary button —
        asks first: they are the only way to ever open the volume."""
        self._pending_shares = list(shares)
        win = tk.Toplevel(self)
        win.title("Recovery Shares")
        win.configure(bg=C["bg"])
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()

        P = SP["xl"]
        k = meta.get("threshold", 2)
        n = meta.get("total", len(shares))
        vol_name = os.path.basename(self._loc_var.get().strip()) or "the volume"
        state = {"saved": False, "copied": False}

        tk.Label(win, text="Save Your Recovery Shares", font=F["heading"],
                 bg=C["bg"], fg=C["text"]).pack(padx=P, pady=(SP["xl"], SP["xs"]))
        tk.Label(win, text=f"You need {k} of {n} shares to unlock this volume.",
                 font=F["body"], bg=C["bg"], fg=C["text3"]).pack(padx=P)
        tk.Label(win, text="Give each share to a different person. Never store "
                           "all shares together.",
                 font=F["caption"], bg=C["bg"], fg=C["warning"]).pack(
            padx=P, pady=(SP["s"], SP["m"]))

        timer_lbl = tk.Label(win, text="", font=F["small"], bg=C["bg"], fg=C["text3"])
        saved_lbl = tk.Label(win, text="", font=F["small"], bg=C["bg"], fg=C["success"],
                             wraplength=self._WRAP, justify="left")
        # Owned by the root so the 60 s clipboard clear outlives this window
        timer = ClipboardTimer(self.master, timer_lbl)

        def _copy(share: str, btn: FlatButton):
            try:
                # Marks the share concealed so clipboard managers skip it, and
                # arms the countdown that wipes only this copy.
                timer.copy(win, share)
            except tk.TclError:
                btn.set_text(f"{ICON['err']} Failed")
                return
            state["copied"] = True
            btn.set_text(f"{ICON['ok']} Copied")
            win.after(1500, lambda: btn.set_text("Copy") if btn.winfo_exists() else None)

        def _copy_event(_event, share: str, btn: FlatButton):
            # ⌘C and the context menu's Copy both raise <<Copy>> on the
            # Text; Tk's stock handler would skip the marker and the wipe.
            _copy(share, btn)
            return "break"

        for i, share in enumerate(shares):
            inner = card(win, padx=SP["m"], pady=SP["s"])
            inner.outer.pack(fill="x", padx=P, pady=(0, SP["xs"] + 2))
            top = tk.Frame(inner, bg=C["surface"])
            top.pack(fill="x")
            tk.Label(top, text=f"Share {i + 1} of {n}", font=F["body_b"],
                     bg=C["surface"], fg=C["text"]).pack(side="left")
            holder: dict = {}
            copy_btn = FlatButton(top, "Copy",
                                  lambda s=share, h=holder: _copy(s, h["btn"]),
                                  primary=False, small=True)
            holder["btn"] = copy_btn
            copy_btn.pack(side="right")
            txt = tk.Text(inner, height=2, wrap="word", font=F["mono_s"],
                          bg=C["surface2"], fg=C["text"], relief="flat",
                          insertbackground=C["accent_text"])
            txt.insert("1.0", share)
            txt.config(state="disabled")
            txt.pack(fill="x", pady=(SP["xs"], 0))
            bind_context_menu(txt)
            txt.bind("<<Copy>>", lambda e, s=share, h=holder: _copy_event(e, s, h["btn"]))

        timer_lbl.pack(padx=P, anchor="w")
        saved_lbl.pack(padx=P, anchor="w")

        def _save_all():
            base = os.path.splitext(os.path.basename(self._loc_var.get().strip()))[0] or "volume"
            p = filedialog.asksaveasfilename(
                title="Save all shares",
                defaultextension=".txt",
                initialfile=f"{base}.shares.txt",
                filetypes=[("Text", "*.txt"), ("All files", "*")],
                parent=win,
            )
            if not p:
                return
            lines = [f"QuantaCrypt recovery shares: {k} of {n} needed", ""]
            for i, share in enumerate(shares):
                lines += [f"Share {i + 1} of {n}:", share, ""]
            try:
                # 0600 + O_EXCL: an existing file with that name is someone's
                # only key material, so this goes to <stem>_2 instead.
                written, renamed = write_new_private_file(p, "\n".join(lines))
            except OSError as e:
                alert(win, "Couldn't save the shares", friendly_error(e))
                return
            state["saved"] = True
            note = (f" A file named {os.path.basename(p)} already existed, so this one "
                    f"was saved as {os.path.basename(written)}." if renamed else "")
            saved_lbl.config(text=f"{ICON['ok']} Saved all {n} shares to "
                                  f"{os.path.basename(written)}. Keep that file somewhere "
                                  f"safe, then split it up.{note}")

        def _finish():
            if not state["saved"]:
                extra = (" Copying isn't enough; the clipboard clears in 60 seconds."
                         if state["copied"] else "")
                ok = confirm(win, "Shares not saved",
                             f"Save the shares first. Without them, {vol_name} can "
                             f"never be opened again.{extra}\n\nLeave and discard the shares?",
                             yes="Leave and discard", no="Go back", danger=True)
                # Tk has no grab stack — the confirm took this window's
                # grab with it; "Go back" must leave the dialog modal.
                try:
                    if win.winfo_exists():
                        win.grab_set()
                except tk.TclError:
                    pass
                if not ok:
                    return
            self._pending_shares = None
            win.destroy()

        btns = tk.Frame(win, bg=C["bg"])
        btns.pack(fill="x", padx=P, pady=(SP["s"], SP["xl"]))
        done_btn = FlatButton(btns, "I've saved all shares", _finish)
        done_btn.pack(side="right")
        FlatButton(btns, "Save all shares…", _save_all,
                   primary=False).pack(side="right", padx=(0, SP["s"]))

        win.bind("<Escape>", lambda e: _finish())
        win.protocol("WM_DELETE_WINDOW", _finish)

        win.update_idletasks()
        cx = self.winfo_x() + self.winfo_width() // 2
        cy = self.winfo_y() + self.winfo_height() // 2
        w, h = win.winfo_width(), win.winfo_height()
        win.geometry(f"+{cx - w // 2}+{cy - h // 2}")
        done_btn.focus_set()
        win.wait_window()

    # ── Mount Panel ──────────────────────────────────────────────────────────

    def _build_mount_panel(self, parent: tk.Frame):
        self._setup_frame: tk.Frame | None = None
        self._mount_inner: tk.Frame | None = None
        if not self._fuse_ok:
            self._setup_frame = tk.Frame(parent, bg=C["bg"])
            self._setup_frame.pack(fill="both", expand=True)
            self._build_setup_screen(self._setup_frame, self._components)
            # Mount UI container (built but hidden until setup is done)
            self._mount_inner = tk.Frame(parent, bg=C["bg"])
            self._build_mount_ui(self._mount_inner)
            return
        self._build_mount_ui(parent)

    # ── Setup screen ─────────────────────────────────────────────────────────

    _COMPONENT_LABELS = {
        "fuse_backend": "Disk mounting support (macFUSE or FUSE-T)"
                        if sys.platform == "darwin" else "Disk mounting support (FUSE)",
        "fusepy": "Mounting helper (fusepy)",
    }

    def _build_setup_screen(self, parent: tk.Frame, components: dict[str, dict]):
        """Guided dependency setup screen shown when FUSE components are missing."""
        tk.Label(parent, text="Setup Required", font=F["heading"],
                 bg=C["bg"], fg=C["warning"]).pack(pady=(SP["m"], SP["xs"]))
        tk.Label(parent, text="Encrypted volumes need two components to mount "
                              "as real drives.",
                 font=F["body"], bg=C["bg"], fg=C["text3"],
                 wraplength=self._WRAP, justify="center").pack(pady=(0, SP["l"]))

        self._comp_widgets: dict[str, dict] = {}
        for key in ("fuse_backend", "fusepy"):
            info = components.get(key, {"ok": False, "detail": "unknown"})
            self._comp_widgets[key] = self._build_component_row(parent, key, info)

        self._recheck_btn = FlatButton(parent, "Check again",
                                       self._recheck_dependencies, primary=False)
        self._recheck_btn.pack(fill="x", pady=(SP["m"], 0))
        self._recheck_lbl = tk.Label(parent, text="", font=F["caption"], bg=C["bg"],
                                     fg=C["text3"], wraplength=self._WRAP, justify="left")
        self._recheck_lbl.pack(anchor="w", pady=(SP["xs"], 0))

    def _build_component_row(self, parent: tk.Frame, key: str, info: dict) -> dict:
        inner = card(parent, padx=SP["m"], pady=SP["s"])
        inner.outer.pack(fill="x", pady=(0, SP["s"]))
        ok = bool(info.get("ok"))

        top = tk.Frame(inner, bg=C["surface"])
        top.pack(fill="x")
        icon_lbl = tk.Label(top, text=ICON["ok"] if ok else ICON["err"], font=F["body_b"],
                            bg=C["surface"], fg=C["success"] if ok else C["error"])
        icon_lbl.pack(side="left")
        tk.Label(top, text=f"  {self._COMPONENT_LABELS[key]}", font=F["body_b"],
                 bg=C["surface"], fg=C["text"]).pack(side="left")

        detail_lbl = tk.Label(inner, text=info.get("detail", ""), font=F["caption"],
                              bg=C["surface"], fg=C["success"] if ok else C["text3"],
                              wraplength=self._WRAP - SP["xl"], justify="left")
        detail_lbl.pack(anchor="w", pady=(2, 0))

        # Instructions / command block, rendered IN the row (never a messagebox)
        cmd_box = tk.Text(inner, height=1, wrap="none", font=F["mono_s"],
                          bg=C["surface2"], fg=C["text"], relief="flat",
                          insertbackground=C["accent_text"])
        bind_context_menu(cmd_box)

        btn_row = tk.Frame(inner, bg=C["surface"])
        btn = extra = None
        if not ok:
            btn_row.pack(fill="x", pady=(SP["s"], 0))
            if key == "fuse_backend":
                btn = FlatButton(btn_row, "How to install…",
                                 self._install_fuse_backend, small=True)
                btn.pack(side="left")
            elif getattr(sys, "frozen", False):
                # In a PyInstaller bundle sys.executable IS the GUI app —
                # "-m pip" would just respawn QuantaCrypt.  fusepy ships
                # inside the bundle, so a missing import means the
                # install is broken, not incomplete.
                detail_lbl.config(text="The helper ships inside the app. This copy "
                                       "is damaged. Download QuantaCrypt again to fix it.")
                btn = FlatButton(btn_row, "Get QuantaCrypt again",
                                 lambda: webbrowser.open(_RELEASES_URL), small=True)
                btn.pack(side="left")
            else:
                cmd = [sys.executable, "-m", "pip", "install", "fusepy"]
                btn = FlatButton(btn_row, "Install helper",
                                 lambda c=cmd: self._run_install(c, "fusepy"), small=True)
                btn.pack(side="left")
                self._set_cmd_box(cmd_box, "pip install fusepy")
                cmd_box.pack(fill="x", pady=(SP["s"], 0))

        return {"row": inner, "icon_lbl": icon_lbl, "detail_lbl": detail_lbl,
                "btn": btn, "btn_row": btn_row, "cmd_box": cmd_box, "extra": extra}

    @staticmethod
    def _set_cmd_box(box: tk.Text, text: str):
        lines = text.count("\n") + 1
        box.config(state="normal", height=lines)
        box.delete("1.0", "end")
        box.insert("1.0", text)
        box.config(state="disabled")

    # Elapsed-seconds ticker for long-running "Installing…" states
    def _start_ticker(self, key: str, base: str):
        self._stop_ticker(key)
        t = {"start": time.time(), "base": base, "job": None}
        self._tickers[key] = t

        def _tick():
            if key not in self._tickers or not self.winfo_exists():
                return
            secs = int(time.time() - t["start"])
            try:
                self._comp_widgets[key]["detail_lbl"].config(
                    text=f"{base} {secs}s", fg=C["warning"])
            except Exception:
                return
            t["job"] = self.after(1000, _tick)
        _tick()

    def _stop_ticker(self, key: str):
        t = self._tickers.pop(key, None)
        if t and t.get("job") is not None:
            try:
                self.after_cancel(t["job"])
            except Exception:
                pass

    def _run_install(self, cmd: list[str], component_key: str):
        """Run a pip install command in a background thread."""
        widgets = self._comp_widgets[component_key]
        if widgets["btn"]:
            widgets["btn"].enable(False)
        self._start_ticker(component_key, "Installing…")

        def _worker():
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120)
                if result.returncode == 0:
                    self._after(lambda: self._on_install_ok(component_key))
                else:
                    err = (result.stderr.strip().splitlines()[-1]
                           if result.stderr.strip() else "Unknown error")
                    self._after(lambda: self._on_install_fail(component_key, err))
            except Exception as e:
                # Bound now: Python unbinds ``e`` when the except block ends,
                # and this lambda runs later on the Tk thread — it raised
                # NameError, the failure was never rendered, the ticker
                # counted on and the button stayed disabled.
                self._after(lambda exc=e: self._on_install_fail(component_key, str(exc)))

        threading.Thread(target=_worker, daemon=True).start()

    def _install_fuse_backend(self):
        """Show install instructions IN the row; on macOS with Homebrew offer
        to open Terminal with the command."""
        widgets = self._comp_widgets["fuse_backend"]
        box: tk.Text = widgets["cmd_box"]
        btn_row: tk.Frame = widgets["btn_row"]
        if widgets["btn"]:
            widgets["btn"].enable(False)

        if sys.platform == "darwin":
            if shutil.which("brew"):
                from quantacrypt.core.fuse_ops import FUSE_INSTALL_ALT, FUSE_INSTALL_CMD
                cmd = FUSE_INSTALL_CMD
                widgets["detail_lbl"].config(
                    text="Needs an administrator password. FUSE-T is recommended "
                         f"(no kernel extension); macFUSE also works: {FUSE_INSTALL_ALT}",
                    fg=C["text3"])
                self._set_cmd_box(box, cmd)
                box.pack(fill="x", pady=(SP["s"], 0))

                def _open_terminal():
                    try:
                        subprocess.Popen([
                            "osascript", "-e",
                            f'tell app "Terminal" to do script "{cmd}"',
                        ])
                    except Exception:
                        widgets["detail_lbl"].config(
                            text="Couldn't open Terminal. Copy the command above "
                                 "and run it yourself.", fg=C["error"])
                        return
                    self._start_ticker("fuse_backend",
                                       "Check Terminal. Install in progress…")
                    term_btn.enable(False)

                term_btn = FlatButton(btn_row, "Open in Terminal", _open_terminal,
                                      primary=False, small=True)
                term_btn.pack(side="left", padx=(SP["s"], 0))
                widgets["extra"] = term_btn
            else:
                widgets["detail_lbl"].config(
                    text="Homebrew isn't installed. Download an installer instead "
                         "(needs an administrator password):", fg=C["text3"])
                self._set_cmd_box(box, f"FUSE-T   {_FUSE_T_URL}\nmacFUSE  {_MACFUSE_URL}")
                box.pack(fill="x", pady=(SP["s"], 0))
        elif sys.platform == "win32":
            widgets["detail_lbl"].config(
                text="Encrypted volumes aren't supported on Windows yet.",
                fg=C["warning"])
        else:
            widgets["detail_lbl"].config(
                text="Install FUSE with your package manager (needs sudo):",
                fg=C["text3"])
            self._set_cmd_box(
                box,
                "sudo apt install libfuse-dev      # Debian / Ubuntu\n"
                "sudo dnf install fuse fuse-devel  # Fedora\n"
                "sudo pacman -S fuse2              # Arch")
            box.pack(fill="x", pady=(SP["s"], 0))
        self._recheck_lbl.config(text="When it's installed, click Check again.")

    def _on_install_ok(self, component_key: str):
        self._stop_ticker(component_key)
        widgets = self._comp_widgets[component_key]
        widgets["icon_lbl"].config(text=ICON["ok"], fg=C["success"])
        widgets["detail_lbl"].config(text="Installed", fg=C["success"])
        if widgets["btn"]:
            widgets["btn"].pack_forget()
        widgets["cmd_box"].pack_forget()
        self._recheck_dependencies()

    def _on_install_fail(self, component_key: str, err: str):
        self._stop_ticker(component_key)
        widgets = self._comp_widgets[component_key]
        widgets["detail_lbl"].config(text=f"Install failed: {err}", fg=C["error"])
        if widgets["btn"]:
            widgets["btn"].enable(True)

    def _recheck_dependencies(self):
        """Re-run component checks; update rows or switch to the mount UI."""
        from quantacrypt.core.fuse_ops import check_fuse_components
        components = check_fuse_components()
        self._components = components
        all_ok = all(c["ok"] for c in components.values())

        missing = []
        for key, info in components.items():
            w = self._comp_widgets.get(key)
            if not w:
                continue
            ok = bool(info["ok"])
            w["icon_lbl"].config(text=ICON["ok"] if ok else ICON["err"],
                                 fg=C["success"] if ok else C["error"])
            if ok:
                self._stop_ticker(key)
                w["detail_lbl"].config(text=info["detail"], fg=C["success"])
                if w["btn"]:
                    w["btn"].pack_forget()
                if w.get("extra"):
                    w["extra"].pack_forget()
                w["cmd_box"].pack_forget()
            else:
                missing.append(self._COMPONENT_LABELS[key].split(" (")[0])
                if key not in self._tickers:
                    w["detail_lbl"].config(text=info["detail"], fg=C["text3"])

        if all_ok:
            self._fuse_ok = True
            self._setup_frame.pack_forget()
            self._mount_inner.pack(fill="both", expand=True)
            self._fuse_warn.outer.pack_forget()
            self._focus_first()
        else:
            self._recheck_lbl.config(
                text=f"Checked just now. Still missing: {', '.join(missing)}.")

    # ── Mount UI ─────────────────────────────────────────────────────────────

    def _build_mount_ui(self, parent: tk.Frame):
        """Build the actual volume mount/unmount controls."""
        tk.Label(parent, text="Volume file (.qcv)", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w", pady=(SP["s"], 0))
        row = tk.Frame(parent, bg=C["bg"])
        row.pack(fill="x", pady=(SP["xs"], 0))
        self._mount_path_var = tk.StringVar()
        self._mount_path_var.trace_add("write", lambda *_: self._on_volume_selected())
        self._mount_path_entry = styled_entry(row, textvariable=self._mount_path_var)
        self._mount_path_entry.pack(side="left", fill="x", expand=True)
        # "Not a valid .qcv" only once the user leaves the field — not per keystroke
        self._mount_path_entry.bind(
            "<FocusOut>", lambda e: self._on_volume_selected(show_errors=True))
        self._mount_path_entry.bind("<Return>", lambda e: self._do_mount())
        FlatButton(row, "Browse…", self._browse_volume,
                   primary=False, small=True).pack(side="left", padx=(SP["s"], 0))

        self._vol_info_lbl = tk.Label(parent, text="", font=F["caption"],
                                      bg=C["bg"], fg=C["text3"], anchor="w",
                                      wraplength=self._WRAP, justify="left")
        self._vol_info_lbl.pack(fill="x", pady=(2, 0))

        # Mount point
        tk.Label(parent, text="Mount point", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w", pady=(SP["s"], 0))
        row2 = tk.Frame(parent, bg=C["bg"])
        row2.pack(fill="x", pady=(SP["xs"], 0))
        self._mount_point_var = tk.StringVar()
        self._mount_point_entry = styled_entry(row2, textvariable=self._mount_point_var)
        self._mount_point_entry.pack(side="left", fill="x", expand=True)
        self._mount_point_entry.bind("<Return>", lambda e: self._do_mount())
        FlatButton(row2, "Choose…", self._browse_mount_point,
                   primary=False, small=True).pack(side="left", padx=(SP["s"], 0))
        tk.Label(parent, text="Filled in from the volume name, a folder in your "
                              "home directory that appears as a drive while mounted.",
                 font=F["caption"], bg=C["bg"], fg=C["text3"],
                 wraplength=self._WRAP, justify="left").pack(anchor="w", pady=(2, 0))

        # Unlock mode
        self._mount_auth_var = tk.StringVar(value="password")
        self._auth_frame = tk.Frame(parent, bg=C["bg"])
        self._auth_frame.pack(fill="x", pady=(SP["m"], 0))
        tk.Label(self._auth_frame, text="Unlock with", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w")
        self._auth_seg = SegmentedControl(
            self._auth_frame,
            [("password", "Password"), ("shamir", "Split key")],
            self._mount_auth_var)
        self._auth_seg.pack(fill="x", pady=(SP["xs"], 0))
        self._mount_auth_var.trace_add("write", lambda *_: self._on_mount_auth_change())

        # Password input
        self._mount_pw_frame = tk.Frame(parent, bg=C["bg"])
        self._mount_pw_frame.pack(fill="x", pady=(SP["s"], 0))
        tk.Label(self._mount_pw_frame, text="Password", font=F["body_b"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w")
        pw_row = tk.Frame(self._mount_pw_frame, bg=C["bg"])
        pw_row.pack(fill="x", pady=(SP["xs"], 0))
        self._mount_pw_var = tk.StringVar()
        self._mount_pw_entry = styled_entry(pw_row, textvariable=self._mount_pw_var, show="•")
        self._mount_pw_entry.pack(side="left", fill="x", expand=True)
        self._mount_pw_entry.bind("<Return>", lambda e: self._do_mount())
        self._mount_pw_show = FlatButton(
            pw_row, "Show",
            lambda: self._toggle_show(self._mount_pw_entry, self._mount_pw_show),
            primary=False, small=True)
        self._mount_pw_show.pack(side="left", padx=(SP["s"], 0))

        # Shares input (hidden by default)
        self._mount_shares_frame = tk.Frame(parent, bg=C["bg"])
        sh_hdr = tk.Frame(self._mount_shares_frame, bg=C["bg"])
        sh_hdr.pack(fill="x")
        tk.Label(sh_hdr, text="Recovery shares",
                 font=F["body_b"], bg=C["bg"], fg=C["text"]).pack(side="left")
        self._mount_load_btn = FlatButton(sh_hdr, "Load from files…",
                                          self._load_mount_shares_from_files,
                                          primary=False, small=True)
        self._mount_load_btn.pack(side="right")
        tk.Label(self._mount_shares_frame,
                 text="Paste one share per line, as QCSHARE- codes or 50-word phrases. "
                      "or load the share files this app saved.",
                 font=F["caption"], bg=C["bg"], fg=C["text3"],
                 wraplength=self._WRAP, justify="left").pack(anchor="w")
        self._mount_shares_text = tk.Text(
            self._mount_shares_frame, height=4, wrap="word",
            font=F["mono_s"], bg=C["surface2"], fg=C["text"],
            relief="flat", insertbackground=C["accent_text"])
        self._mount_shares_text.pack(fill="x", pady=(SP["xs"], 0))
        bind_context_menu(self._mount_shares_text)

        # Progress bar (M24) — packed only while a mount runs
        self._mount_prog = StagedProgressBar(parent, _MOUNT_STAGES)

        # Mount button + inline error + status
        self._mount_btn = FlatButton(parent, f"Mount volume {ICON['arrow']}", self._do_mount)
        self._mount_btn.pack(fill="x", pady=(SP["l"], 0))
        self._mount_err = tk.Label(parent, text="", font=F["caption"], bg=C["bg"],
                                   fg=C["error"], anchor="w", justify="left",
                                   wraplength=self._WRAP)
        self._mount_err.pack(fill="x", pady=(SP["s"], 0))
        self._mount_status = tk.Label(parent, text="", font=F["caption"],
                                      bg=C["bg"], fg=C["text3"], anchor="w",
                                      wraplength=self._WRAP, justify="left")
        self._mount_status.pack(fill="x")

        # ── Mounted volumes list ──
        self._mounted_list_frame = tk.Frame(parent, bg=C["bg"])
        self._mounted_list_frame.pack(fill="x", pady=(SP["s"], 0))
        self._refresh_mounted_list(force=True)

    def _default_mount_point(self, volume_path: str) -> str:
        base = os.path.splitext(os.path.basename(volume_path))[0] or "Volume"
        return os.path.expanduser(os.path.join("~", "QuantaCrypt Volumes", base))

    def _on_volume_selected(self, show_errors: bool = False):
        """Volume path changed: detect the unlock mode from the cleartext auth
        params, show size, and suggest a mount point (without clobbering one
        the user typed)."""
        path = self._mount_path_var.get().strip()
        if not path or not os.path.isfile(path):
            if show_errors and path:
                self._vol_info_lbl.config(text="That file doesn't exist.", fg=C["error"])
            else:
                self._vol_info_lbl.config(text="")
            return

        try:
            _header, auth_params = vol.read_volume_auth_params(path)
        except (ValueError, OSError, TypeError):
            if show_errors:
                self._vol_info_lbl.config(text="Not a valid .qcv file", fg=C["error"])
            else:
                self._vol_info_lbl.config(text="")
            return

        mode = auth_params["mode"]        # required by read_volume_auth_params
        try:
            size_hint = f"  ·  file on disk {fmt_size(os.path.getsize(path))}"
        except OSError:
            size_hint = ""

        if mode == "shamir":
            self._mount_auth_var.set("shamir")
            k = auth_params.get("threshold", "?")
            n = auth_params.get("total", "?")
            self._vol_info_lbl.config(
                text=f"Split-key volume: needs {k} of {n} shares{size_hint}",
                fg=C["text3"])
        else:
            self._mount_auth_var.set("password")
            self._vol_info_lbl.config(
                text=f"Password-protected volume{size_hint}", fg=C["text3"])

        # Q25: suggest ~/QuantaCrypt Volumes/<name>, but only over an empty
        # field or our own previous suggestion — never over a user edit.
        current = self._mount_point_var.get().strip()
        if not current or current == self._auto_mp:
            self._auto_mp = self._default_mount_point(path)
            self._mount_point_var.set(self._auto_mp)

    def _on_mount_auth_change(self):
        if self._mount_auth_var.get() == "password":
            self._mount_shares_frame.pack_forget()
            self._mount_pw_frame.pack(fill="x", pady=(SP["s"], 0), after=self._auth_frame)
        else:
            self._mount_pw_frame.pack_forget()
            self._mount_shares_frame.pack(fill="x", pady=(SP["s"], 0), after=self._auth_frame)

    def _browse_volume(self):
        p = filedialog.askopenfilename(
            title="Select encrypted volume",
            filetypes=[("QuantaCrypt Volume", "*.qcv"), ("All files", "*")],
            initialdir=os.path.expanduser("~"),
            parent=self,
        )
        if p:
            self._mount_path_var.set(p)
            self._on_volume_selected(show_errors=True)
            self._focus_first()

    def _browse_mount_point(self):
        p = filedialog.askdirectory(title="Select mount point", parent=self)
        if p:
            self._mount_point_var.set(p)

    def _load_mount_shares_from_files(self):
        """Open share files (this screen's "Save all shares…" file, the
        encryptor's .share-N-of-M.txt, any text with QCSHARE- codes or
        50-word phrases) and append the shares found to the text box — one
        per line, skipping ones already there.  Same pattern and 1 MB cap
        as the decryptor's "Load from file…"."""
        if self._busy:
            return
        vol_path = self._mount_path_var.get().strip()
        paths = filedialog.askopenfilenames(
            parent=self, title="Choose share files",
            filetypes=[("Share files", "*.txt"), ("All files", "*")],
            initialdir=os.path.dirname(vol_path) if vol_path else os.path.expanduser("~"))
        if not paths:
            return
        codes, unreadable = [], []
        for p in paths:
            try:
                if os.path.getsize(p) > _MAX_SHARE_FILE:
                    unreadable.append(os.path.basename(p)); continue
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                unreadable.append(os.path.basename(p)); continue
            for c in pkg.extract_share_codes(text):
                if c not in codes:
                    codes.append(c)
        where = "that file" if len(paths) == 1 else "those files"
        if unreadable:
            self._fail_mount(f"Couldn't read {', '.join(unreadable)}.")
        if not codes:
            alert(self, "No shares found",
                  f"No QCSHARE- codes or 50-word phrases were found in {where}.")
            return
        present = set(_parse_share_text(self._mount_shares_text.get("1.0", "end")))
        new = [c for c in codes if c not in present]
        if new:
            existing = self._mount_shares_text.get("1.0", "end").strip()
            self._mount_shares_text.insert(
                "end", ("\n" if existing else "") + "\n".join(new) + "\n")
        self._mount_err.config(text="")
        n = len(new)
        self._set_status(f"Loaded {n} share{'s' if n != 1 else ''} from {where}."
                         + ("" if n == len(codes) else
                            f" {len(codes) - n} already in the box."))
        self._mount_shares_text.focus_set()

    def _fail_mount(self, msg: str, focus: tk.Widget | None = None):
        self._mount_err.config(text=msg)
        if focus is not None:
            focus.focus_set()

    def _do_mount(self):
        if self._busy:
            return
        self._mount_err.config(text="")
        vol_path = os.path.expanduser(self._mount_path_var.get().strip())
        mount_point = os.path.expanduser(self._mount_point_var.get().strip())

        if not vol_path or not os.path.isfile(vol_path):
            self._fail_mount("Select a valid .qcv file.", self._mount_path_entry)
            return
        if not mount_point:
            self._fail_mount("Choose a mount point.", self._mount_point_entry)
            return

        # Tk widget reads are not thread-safe — capture credential state on
        # the main thread before handing off to the worker (same pattern as
        # the encryptor/decryptor wizards).
        pw = self._mount_pw_var.get()
        shares_text = self._mount_shares_text.get("1.0", "end").strip()
        if self._mount_auth_var.get() == "password" and not pw:
            self._fail_mount("Enter the password.", self._mount_pw_entry)
            return
        if self._mount_auth_var.get() == "shamir" and not shares_text:
            self._fail_mount("Paste your recovery shares.", self._mount_shares_text)
            return

        self._busy = True
        self._busy_what = "mount"
        self._mount_btn.enable(False)
        self._set_status("", expire=False)
        self._mount_prog.pack(fill="x", pady=(SP["m"], 0), before=self._mount_btn)
        self._mount_prog.start()
        self._mount_prog.advance(0)

        # Emergency-save signal handlers can only be installed from the
        # main thread; the mount itself runs on a worker (see fuse_ops
        # _ensure_shutdown_handlers for why the worker's attempt can't).
        from quantacrypt.core.fuse_ops import install_shutdown_handlers
        install_shutdown_handlers()

        def _stage(i):
            self._after(lambda: self._mount_prog.advance(i))

        def _worker():
            try:
                # Read unencrypted auth params (no key needed)
                header, auth_params = vol.read_volume_auth_params(vol_path)
                mode = auth_params["mode"]    # required by read_volume_auth_params

                _stage(1)
                if mode == "single":
                    if not pw:
                        self._after(lambda: self._mount_error("Enter the password."))
                        return
                    final_key = vol.derive_volume_key_single(pw, auth_params)
                else:
                    if not shares_text:
                        self._after(lambda: self._mount_error(
                            "Paste your recovery shares."))
                        return
                    # Same share syntax as qc-core: codes or mnemonics,
                    # de-duplicated, first k used.
                    codes = pkg.normalize_shares(_parse_share_text(shares_text))
                    k = auth_params.get("threshold") or len(codes)
                    if len(codes) < k:
                        self._after(lambda: self._mount_error(
                            f"Need {k} different shares to open this volume, "
                            f"got {len(codes)}."))
                        return
                    final_key = vol.derive_volume_key_shamir(codes[:k], auth_params)

                # Mount via FUSE (mount_volume opens the volume internally)
                _stage(2)
                from quantacrypt.core.fuse_ops import mount_volume
                # The key came out of this volume's own auth block, so a
                # metadata failure inside open() is tampering, not a typo.
                fuse_obj = mount_volume(vol_path, final_key, mount_point,
                                        credential_proven=True)

                suspicious = fuse_obj.volume.journal_suspicious
                sidecar = getattr(fuse_obj.volume, "suspect_sidecar", None)
                read_only = bool(getattr(fuse_obj.volume, "read_only", False))
                self._after(lambda: self._on_mount_done(
                    vol_path, mount_point, auth_params, suspicious=suspicious,
                    sidecar=sidecar, read_only=read_only))

            except Exception as e:
                self._after(lambda exc=e: self._mount_error(exc, mount_point))

        threading.Thread(target=_worker, daemon=True).start()

    def _end_mount_busy(self):
        self._busy = False
        self._busy_what = ""
        self._mount_btn.enable(True)

    def _on_mount_done(self, vol_path: str, mount_point: str, auth_params: dict,
                       suspicious: bool = False, sidecar: str | None = None,
                       read_only: bool = False):
        self._mount_prog.complete()
        self._after(lambda: self._mount_prog.pack_forget(), 1200)
        self._end_mount_busy()
        self._mount_pw_var.set("")
        self._mount_shares_text.delete("1.0", "end")
        RecentVolumes.add(vol_path, auth_params)
        if read_only:
            # The container or its folder refuses writes (read-only media,
            # a locked share): say so before the first failed copy does.
            self._set_status(
                f"{ICON['ok']} Mounted read-only at {mount_point} — the .qcv "
                "file or its folder can't be written", C["warning"])
        else:
            self._set_status(f"{ICON['ok']} Mounted at {mount_point}", C["success"])
        self._refresh_mounted_list(force=True)
        if not suspicious:
            notify("Volume Mounted", f"Encrypted volume mounted at {mount_point}")
            return
        # open() found a fully-present journal record failing
        # authentication — the shape of tampering or rollback, not of
        # a crash.  Warn BEFORE the user writes: the first save
        # truncates the suspicious tail, destroying the evidence.
        name = os.path.basename(vol_path)
        # The unreadable tail was copied beside the volume before the first
        # save overwrites it.  Evidence nobody is told about is
        # indistinguishable from litter, so name the file.
        kept = (f"The unreadable records were saved to {os.path.basename(sidecar)} "
                "beside the volume; keep it with your backup if you want to "
                "look into this.\n\n") if sidecar else ""
        if confirm(
                self, "This volume may have been altered",
                f"{name}'s records don't match what QuantaCrypt last wrote. "
                "It may have been altered or swapped for an older copy. It was "
                "mounted using the last state that checks out.\n\n"
                f"{kept}"
                "If you didn't expect this, unmount now and keep a copy of the "
                ".qcv file before writing anything.",
                yes="Unmount now", no="Keep mounted", danger=True):
            self._do_unmount(mount_point, confirmed=True)

    def _mount_error(self, msg, mount_point: str = ""):
        self._mount_prog.stop()
        self._mount_prog.pack_forget()
        self._end_mount_busy()
        focus = None
        if (isinstance(msg, PermissionError) and mount_point
                and _blames_mount_point(msg, mount_point)):
            # Q25: user processes can't create folders under /Volumes on
            # modern macOS — name the fix instead of "Access denied".
            name = os.path.basename(mount_point.rstrip("/")) or "<name>"
            if sys.platform == "darwin" and mount_point.startswith("/Volumes"):
                msg = ("macOS doesn't let apps create folders in /Volumes. Use a "
                       "folder in your home directory, e.g. "
                       f"~/QuantaCrypt Volumes/{name}.")
            else:
                msg = (f"Couldn't create the mount point folder at {mount_point}: "
                       "pick a folder you're allowed to write to.")
            focus = self._mount_point_entry
        elif isinstance(msg, BaseException):
            msg = f"Couldn't mount: {friendly_error(msg)}"
            if "password" in msg.lower() or "share" in msg.lower():
                focus = (self._mount_pw_entry if self._mount_auth_var.get() == "password"
                         else self._mount_shares_text)
        self._fail_mount(str(msg), focus)

    # ── Unmount ──────────────────────────────────────────────────────────────

    def _do_unmount(self, mount_point: str, *, confirmed: bool = False):
        """Confirm → unmount on a worker thread → row shows 'Unmounting…'."""
        if mount_point in self._unmounting:
            return
        from quantacrypt.core.fuse_ops import get_mounted_volumes, unmount_volume
        info = get_mounted_volumes().get(mount_point, {})
        name = os.path.basename(info.get("volume_path", "")) or os.path.basename(mount_point)
        if not confirmed and not confirm(
                self, f"Unmount {name}?",
                f"Anything still open from {mount_point} may lose unsaved work. "
                "Close those files first.",
                yes="Unmount", no="Keep mounted", danger=True):
            return

        self._unmounting.add(mount_point)
        self._row_notes.pop(mount_point, None)
        row = self._rows.get(mount_point)
        if row:
            self._set_row_busy(row, "Unmounting…")

        def _worker():
            try:
                unmount_volume(mount_point)
                err = None
            except Exception as e:
                err = e
            self._after(lambda: self._on_unmount_done(mount_point, name, err))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_unmount_done(self, mount_point: str, name: str, err: BaseException | None):
        self._unmounting.discard(mount_point)
        if err is None:
            self._set_status(f"{ICON['ok']} Unmounted {name}", C["success"])
            self._empty_note = f"Unmounted {name}."
            self._refresh_mounted_list(force=True)
            return
        from quantacrypt.core.errors import InvalidInput
        if isinstance(err, InvalidInput):
            # Already ejected out from under us (an external umount between
            # the poll and the click): not an error to alert on.
            self._set_status(f"{ICON['ok']} {name} was already unmounted", C["success"])
            self._empty_note = f"{name} was already unmounted."
            self._refresh_mounted_list(force=True)
            return
        detail = friendly_error(err)
        self._row_notes[mount_point] = (
            f"{ICON['err']} Couldn't unmount. Something is still using it.", C["error"])
        self._refresh_mounted_list(force=True)
        self._set_status(f"Couldn't unmount {name}", C["error"])
        alert(self, f"Couldn't unmount {name}",
              f"Something is still using {name}. Close any Finder windows or apps "
              "opened from it, then try Unmount again.\n\n"
              f"{detail}")

    @staticmethod
    def _set_row_busy(row: dict, text: str):
        for b in row["buttons"]:
            b.enable(False)
        row["note"].config(text=text, fg=C["text3"])
        row["note"].pack(anchor="w", pady=(2, 0))

    def _reveal_mount(self, mount_point: str):
        if not reveal_path(mount_point):
            self._row_notes[mount_point] = (
                f"Couldn't open the file manager. It's at {mount_point}", C["warning"])
            self._refresh_mounted_list(force=True)

    # ── Mounted list ─────────────────────────────────────────────────────────

    def _schedule_refresh(self):
        self._refresh_job = self.after(self._REFRESH_MS, self._poll_mounted)

    def _poll_mounted(self):
        """Periodic refresh.  The snapshot (get_mounted_volumes takes the
        mount lock, which an unmount holds across ``diskutil``; stat()
        walks the directory index) runs on a worker so a busy unmount can't
        freeze the window; only the rendering hops back here."""
        self._refresh_job = None
        if not self.winfo_exists():
            return

        def _worker():
            try:
                snap = self._snapshot_mounted()
            except Exception:
                snap = None

            def _apply():
                if snap is not None:
                    try:
                        self._render_mounted(*snap)
                    except Exception:
                        pass
                self._schedule_refresh()
            self._after(_apply)

        threading.Thread(target=_worker, daemon=True).start()

    @staticmethod
    def _stats_text(info: dict) -> str:
        vc = info.get("volume")
        if vc is None:
            return ""
        try:
            stats = vc.stat()
        except Exception:
            return "Size unavailable"
        parts = []
        fc = stats.get("file_count", 0)
        dc = stats.get("dir_count", 0)
        parts.append(f"{fc} file{'s' if fc != 1 else ''}")
        if dc:
            parts.append(f"{dc} folder{'s' if dc != 1 else ''}")
        parts.append(fmt_size(stats.get("total_plaintext_size", 0)))
        cs = stats.get("container_size", 0)
        if cs:
            parts.append(f"file on disk {fmt_size(cs)}")
        return "  ·  ".join(parts)

    def _snapshot_mounted(self) -> tuple[dict, dict]:
        """``(mounted, stats_text_by_mount_point)`` — safe to call off the
        main thread (no widget access)."""
        from quantacrypt.core.fuse_ops import get_mounted_volumes
        mounted = get_mounted_volumes()
        return mounted, {mp: self._stats_text(info) for mp, info in mounted.items()}

    def _refresh_mounted_list(self, force: bool = False):
        """Synchronous refresh for the moments right after our own mount /
        unmount (the lock is free then); the periodic poll goes through
        ``_poll_mounted`` on a worker."""
        self._render_mounted(*self._snapshot_mounted(), force=force)

    def _render_mounted(self, mounted: dict, stats: dict, force: bool = False):
        """Rebuild the mounted-volumes list when the set of mounts changed
        (external ejects disappear); otherwise just refresh the stats lines
        so hover/focus on the row buttons is not disturbed."""
        key = tuple(sorted(mounted))
        if not force and key == self._last_mounted_key:
            for mp, row in self._rows.items():
                if mp in mounted:
                    row["stats"].config(text=stats.get(mp, ""))
            return
        self._last_mounted_key = key

        for w in self._mounted_list_frame.winfo_children():
            w.destroy()
        self._rows = {}

        section_label(self._mounted_list_frame, "MOUNTED VOLUMES", padx=0)
        if not mounted:
            note = self._empty_note
            self._empty_note = ""
            tk.Label(self._mounted_list_frame,
                     text=f"No volumes mounted. {note}".strip(),
                     font=F["caption"], bg=C["bg"], fg=C["text3"]).pack(anchor="w")
            return

        for mp, info in mounted.items():
            vol_name = os.path.basename(info.get("volume_path", "?"))
            inner = card(self._mounted_list_frame, padx=SP["m"], pady=SP["s"])
            inner.outer.pack(fill="x", pady=(0, SP["xs"]))

            top = tk.Frame(inner, bg=C["surface"])
            top.pack(fill="x")
            names = tk.Frame(top, bg=C["surface"])
            names.pack(side="left", fill="x", expand=True)
            tk.Label(names, text=vol_name, font=F["body_b"],
                     bg=C["surface"], fg=C["text"]).pack(anchor="w")
            tk.Label(names, text=mp, font=F["caption"],
                     bg=C["surface"], fg=C["text3"]).pack(anchor="w")
            if info.get("read_only"):
                # The one-shot status line is overwritten by the next
                # action; the row is what the user looks at before dragging.
                tk.Label(names, text="Read-only — the .qcv file or its folder can't be written",
                         font=F["caption"], bg=C["surface"], fg=C["warning"]).pack(anchor="w")

            btn_frame = tk.Frame(top, bg=C["surface"])
            btn_frame.pack(side="right")
            reveal_btn = FlatButton(btn_frame, REVEAL_LABEL,
                                    lambda p=mp: self._reveal_mount(p),
                                    primary=False, small=True)
            reveal_btn.pack(side="left", padx=(0, SP["xs"]))
            unmount_btn = FlatButton(btn_frame, "Unmount",
                                     lambda p=mp: self._do_unmount(p),
                                     primary=False, small=True)
            unmount_btn.pack(side="left")

            stats_lbl = tk.Label(inner, text=stats.get(mp, ""), font=F["small"],
                                 bg=C["surface"], fg=C["text3"])
            stats_lbl.pack(anchor="w", pady=(2, 0))
            # Row-level feedback (unmount/reveal outcome) lives in the row
            note = tk.Label(inner, text="", font=F["small"], bg=C["surface"],
                            fg=C["text3"], wraplength=self._WRAP - SP["xl"],
                            justify="left")

            row = {"buttons": (reveal_btn, unmount_btn), "stats": stats_lbl, "note": note}
            self._rows[mp] = row
            if mp in self._unmounting:
                self._set_row_busy(row, "Unmounting…")
            elif mp in self._row_notes:
                text, fg = self._row_notes.pop(mp)
                note.config(text=text, fg=fg)
                note.pack(anchor="w", pady=(2, 0))
