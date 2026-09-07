#!/usr/bin/env python3
"""QuantaCrypt Launcher — home screen for the combined binary."""
import os
import sys
import tkinter as tk

from quantacrypt import __version__
from quantacrypt.ui.shared import (
    C, F, SP, ICON,
    accel, bind_shortcut, card, kv_row, fmt_size, friendly_error,
    FlatButton, RecentFiles, AppPrefs,
)

try:
    from tkinterdnd2 import DND_FILES as _DND_FILES, TkinterDnD as _TkDnD
except ImportError:
    _DND_FILES = None
    _TkDnD = None  # type: ignore[assignment,misc]

# Type alias: the launcher's master may be a plain Tk or a TkinterDnD.Tk,
# and the launcher itself gains dnd methods at runtime when tkinterdnd2 is
# available.  We use TYPE_CHECKING to keep the static analyser happy.
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

# Window width.  Everything below wraps to this so the launcher stays one
# column and fits a 13" display with the Recent list open.
_W = 520
_RECENT_VISIBLE = 3


class LauncherApp(tk.Toplevel):
    # DnD methods are injected at runtime by tkinterdnd2; declare for type-checkers
    drop_target_register: "Any"
    dnd_bind: "Any"

    def __init__(self, master: "tk.Misc"):
        super().__init__(master)
        self.title("QuantaCrypt")
        self.configure(bg=C["bg"])
        # Vertical resize only: the Recent list can grow past a small screen
        # and pack() has no scroll; letting the user pull the window taller
        # is the one-line mitigation.
        self.resizable(False, True)
        self._build()
        self._center()
        # Check for updates in the background (non-blocking)
        from quantacrypt.ui.updater import check_for_update
        check_for_update(self, __version__)
        # Keyboard shortcuts: ⌘ on macOS (Ctrl also accepted), Ctrl elsewhere.
        # M for volumes, not V — ⌘V is Paste on macOS.
        bind_shortcut(self, "e", self._open_encryptor)
        bind_shortcut(self, "d", self._open_decryptor)
        bind_shortcut(self, "m", self._open_volumes)
        bind_shortcut(self, "i", self._inspect_file)
        # No Escape-to-quit: Escape must never be a data-loss key.  ⌘W / ⌘Q
        # on the main window mean quit (with the mounted-volume guard).
        if sys.platform == "darwin":
            bind_shortcut(self, "w", self._quit_app, also_control=False)
            bind_shortcut(self, "q", self._quit_app, also_control=False)
        self.protocol("WM_DELETE_WINDOW", self._quit_app)
        # Drag-and-drop: drop a .qcx → open decryptor
        if _DND_FILES:
            try:
                self.drop_target_register(_DND_FILES)
                self.dnd_bind("<<Drop>>", self._on_drop)
            except Exception:
                pass

    def can_quit(self) -> bool:
        """Whether the app may quit given what is mounted — a pure predicate
        (it may still unmount, which is what quitting entails), shared with
        the Quit Apple event so every window is asked before anything is torn
        down (review run 20 F-005)."""
        try:
            from quantacrypt.core.fuse_ops import (
                get_mounted_volumes, unmount_volume)
            mounted = list(get_mounted_volumes())
        except Exception:
            mounted = []
        if not mounted:
            return True
        from tkinter import messagebox
        n = len(mounted)
        noun = "volume" if n == 1 else f"{n} volumes"
        if not messagebox.askyesno(
                "Volumes mounted",
                f"You still have {noun} mounted:\n"
                + "\n".join(f"  • {mp}" for mp in mounted[:5])
                + ("\n  …" if n > 5 else "")
                + "\n\nUnmount and quit?",
                icon="warning", default="yes", parent=self):
            return False
        failed = []
        for mp in mounted:
            try:
                unmount_volume(mp)
            except Exception as exc:
                failed.append(f"{mp}: {exc}")
        if failed:
            messagebox.showerror(
                "Unmount failed",
                "Some volumes could not be unmounted (files may be "
                "in use):\n\n" + "\n".join(failed)
                + "\n\nClose the files using them, then quit again.",
                parent=self)
            return False
        return True

    def _quit_app(self):
        """Quit, unmounting any live volumes first (the launcher's own ⌘Q /
        close button; the Apple-event hook drives ``can_quit`` directly)."""
        if not self.can_quit():
            return
        from quantacrypt.ui.shared import ClipboardTimer
        ClipboardTimer.wipe_all()
        self.master.destroy()

    def _on_drop(self, event):
        try:
            paths = self.tk.splitlist(event.data)
        except Exception:
            # Fallback for non-standard Tcl encoding
            raw = event.data.strip()
            if raw.startswith("{") and raw.endswith("}"): raw = raw[1:-1]
            paths = [raw.split("} {")[0]]
        # Accept any combination of .qcx / .qcv files dropped together.
        # Previously we only honoured paths[0] and silently lost the rest;
        # for multi-file drops this looked like an app bug.  We only open
        # one wizard window at a time (the remaining paths queue behind
        # the first on the Tk event loop via after()).
        accepted = [
            p for p in paths
            if os.path.isfile(p)
            and os.path.splitext(p)[1].lower() in (".qcx", ".qcv")
        ]
        if not accepted:
            self._set_hint("Drop a .qcx or .qcv file. Other files can't be opened here.",
                           error=True)
            return

        def _dispatch(path: str):
            ext = os.path.splitext(path)[1].lower()
            if ext == ".qcv":
                self._open_volumes(volume_path=path)
            else:
                self._open_qcx(path)

        # Multi-drop policy: every accepted path opens its own wizard
        # window (same pattern as Finder's "Open With..." on multi-select).
        # The after(1, ...) just yields back to the Tk event loop between
        # dispatches so constructors don't all fire in one tick — it does
        # NOT wait for the first wizard to close.  If a future release
        # wants a true serial queue (open-then-close-then-next), thread
        # the chain through each wizard's on_close callback.
        _dispatch(accepted[0])
        for extra in accepted[1:]:
            self.after(1, lambda p=extra: _dispatch(p))

    def _center(self):
        self.update_idletasks()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h   = self.winfo_width(), self.winfo_height()
        self.geometry(f"+{(sw-w)//2}+{max(0, (sh-h)//2)}")

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        P = SP["xxl"]

        # ── Title ─────────────────────────────────────────────────────────────
        top = tk.Frame(self, bg=C["bg"])
        top.pack(fill="x", padx=P, pady=(SP["xl"], 0))
        tk.Label(top, text="QuantaCrypt", font=F["display"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w")
        tk.Label(top, text="Post-quantum file encryption",
                 font=F["caption"], bg=C["bg"], fg=C["text3"]).pack(anchor="w")

        # Slot the update banner packs into (see updater.py) — a named frame
        # so the banner never has to guess at child indices.
        self._banner_slot = tk.Frame(self, bg=C["bg"])
        self._banner_slot.pack(fill="x", padx=P)

        # ── Three entry points, one per row ───────────────────────────────────
        # Rows instead of tiles: no orphaned third card, denser, and the
        # list scales if a fourth entry point ever appears.  The row whose
        # mode was used last carries the accent; the others stay quiet.
        last = AppPrefs.get("last_mode", "encrypt")
        rows = tk.Frame(self, bg=C["bg"])
        rows.pack(fill="x", padx=P, pady=(SP["l"], 0))
        self._enc_card = self._make_row(
            rows, "Encrypt",
            "Protect a file with a password, or split the key between people.",
            f"Encrypt a file {ICON['arrow']}", self._open_encryptor,
            accent=(last == "encrypt"))
        self._dec_card = self._make_row(
            rows, "Decrypt",
            "Open a .qcx file with its password or shares.",
            f"Decrypt a file {ICON['arrow']}", self._open_decryptor,
            accent=(last == "decrypt"))
        self._vol_card = self._make_row(
            rows, "Volumes",
            "Create or mount an encrypted drive (.qcv) that works like a folder.",
            f"Manage volumes {ICON['arrow']}", self._open_volumes,
            accent=(last == "volumes"))

        # ── Secondary: inspect + hint line ────────────────────────────────────
        tools = tk.Frame(self, bg=C["bg"])
        tools.pack(fill="x", padx=P, pady=(SP["m"], 0))
        FlatButton(tools, "Inspect a .qcx file without the password",
                   self._inspect_file, primary=False, small=True).pack(side="left")

        # The drop hint is only shown when a drop target was actually
        # registered (tkinterdnd2 present) — otherwise it would be a lie.
        self._hint = tk.Label(self, text="", font=F["small"],
                              bg=C["bg"], fg=C["text3"], wraplength=_W - 2 * P,
                              justify="left", anchor="w")
        self._hint.pack(fill="x", padx=P, pady=(SP["xs"], 0))
        if _DND_FILES:
            self._set_hint("You can also drop a .qcx or .qcv file onto this window.")

        # ── Recent files ───────────────────────────────────────────────────────
        self._recent_frame = tk.Frame(self, bg=C["bg"])
        self._recent_frame.pack(fill="x", padx=P, pady=(SP["m"], 0))
        try:
            self._build_recent()
        except Exception:
            pass   # a broken recents store must not stop the app opening

        # ── Footer: version + shortcuts on one line ───────────────────────────
        sc = "  ·  ".join([
            f"{accel('E')} Encrypt", f"{accel('D')} Decrypt",
            f"{accel('M')} Volumes", f"{accel('I')} Inspect",
        ])
        tk.Label(self, text=f"v{__version__}   {sc}",
                 font=F["small"], bg=C["bg"], fg=C["text3"],
                 wraplength=_W - 2 * P, justify="left", anchor="w").pack(
            fill="x", padx=P, pady=(SP["l"], SP["l"]))

    def _set_hint(self, text, error=False):
        self._hint.config(text=text, fg=C["error"] if error else C["text3"])
        if error:
            self.after(6000, lambda: self._hint.config(
                text="You can also drop a .qcx or .qcv file onto this window."
                     if _DND_FILES else "", fg=C["text3"]))

    def _make_row(self, parent, title, body, btn_text, command, accent):
        """One full-width entry point: title + one-line description on the
        left, its action button on the right.  Whole row is focusable and
        activates with Return/Space; hover/focus are shown on the border so
        the button inside never merges with a recoloured background."""
        inner = card(parent, padx=SP["l"], pady=SP["m"])
        row = inner.outer
        row.pack(fill="x", pady=(0, SP["s"]))

        text = tk.Frame(inner, bg=C["surface"])
        text.pack(side="left", fill="x", expand=True)
        tk.Label(text, text=title, font=F["heading"],
                 bg=C["surface"], fg=C["text"], anchor="w").pack(anchor="w")
        tk.Label(text, text=body, font=F["caption"], bg=C["surface"],
                 fg=C["text3"], justify="left", anchor="w",
                 wraplength=_W - 2 * SP["xxl"] - 2 * SP["l"] - 170).pack(anchor="w", pady=(2, 0))

        btn = FlatButton(inner, btn_text, command, primary=accent, small=True)
        btn.pack(side="right", padx=(SP["m"], 0))

        def _focus_ring(on):
            row.config(highlightbackground=C["accent_text"] if on else C["border"],
                       highlightthickness=2 if on else 1)

        row.config(takefocus=True, cursor="hand2")
        for w in (row, inner, text) + tuple(text.winfo_children()):
            w.bind("<Button-1>", lambda e: command())
        row.bind("<Return>", lambda e: command())
        row.bind("<space>",  lambda e: command())
        row.bind("<FocusIn>",  lambda e: _focus_ring(True))
        row.bind("<FocusOut>", lambda e: _focus_ring(False))
        row.bind("<Enter>", lambda e: row.config(highlightbackground=C["surface3"])
                 if row.focus_get() is not row else None)
        row.bind("<Leave>", lambda e: row.config(highlightbackground=C["border"])
                 if row.focus_get() is not row else None)
        return row

    # ── Recent files ─────────────────────────────────────────────────────────

    def _build_recent(self):
        """Render or refresh the recent .qcx files list."""
        for w in self._recent_frame.winfo_children():
            w.destroy()
        entries = RecentFiles.load()
        if not entries:
            return
        hdr = tk.Frame(self._recent_frame, bg=C["bg"])
        hdr.pack(fill="x", pady=(0, SP["xs"]))
        tk.Label(hdr, text="RECENTLY DECRYPTED", font=F["small"],
                 bg=C["bg"], fg=C["text3"]).pack(side="left")
        def _do_clear():
            if not RecentFiles.clear():
                from quantacrypt.ui.shared import alert
                alert(self, "Couldn't clear the list",
                      "The recent-files list could not be rewritten, so it is "
                      "still stored. Check that your home folder is writable.")
                return
            self._build_recent()
        FlatButton(hdr, "Clear", _do_clear, primary=False, small=True).pack(side="right")
        for path, entry in entries[:_RECENT_VISIBLE]:
            self._build_recent_row(path, entry)
        # Cap the visible rows so the launcher never outgrows the screen
        if len(entries) > _RECENT_VISIBLE:
            extra = len(entries) - _RECENT_VISIBLE
            tk.Label(self._recent_frame,
                     text=f"… and {extra} more (use Decrypt to browse)",
                     font=F["small"], bg=C["bg"], fg=C["text3"]).pack(anchor="w")

    def _build_recent_row(self, path, entry):
        """Render a single recent-file row inside ``_recent_frame``."""
        import time as _t

        mode = entry.get("mode", "single")
        k, n = entry.get("threshold", 0), entry.get("total", 0)
        mode_tag = (f"Split key ({k} of {n})" if mode == "shamir" and k and n
                    else "Password")
        ts = entry.get("ts", 0)
        try:
            date_str = _t.strftime("%b %d", _t.localtime(ts)) if ts else ""
        except Exception:
            date_str = ""

        inner = card(self._recent_frame, padx=SP["m"], pady=SP["s"])
        row = inner.outer
        row.pack(fill="x", pady=(0, SP["xs"]))
        top_inner = tk.Frame(inner, bg=C["surface"])
        top_inner.pack(fill="x")
        name_lbl = tk.Label(top_inner, text=os.path.basename(path),
                            font=F["caption"], bg=C["surface"], fg=C["text"])
        name_lbl.pack(side="left")
        combined_meta = "  ·  ".join(x for x in [mode_tag, date_str] if x)
        meta_lbl = tk.Label(top_inner, text=combined_meta,
                            font=F["small"], bg=C["surface"], fg=C["text3"])
        meta_lbl.pack(side="right")
        dir_lbl = tk.Label(inner, text=os.path.dirname(path),
                           font=F["small"], bg=C["surface"], fg=C["text3"],
                           anchor="w")
        dir_lbl.pack(fill="x")

        def _ring(on):
            row.config(highlightbackground=C["accent_text"] if on else C["border"],
                       highlightthickness=2 if on else 1)

        # Rows are real targets: focusable, Return/Space, visible ring.
        row.config(takefocus=True, cursor="hand2")
        for w in (row, inner, top_inner, name_lbl, meta_lbl, dir_lbl):
            w.bind("<Button-1>", lambda e, p=path: self._open_qcx(p))
        row.bind("<Return>", lambda e, p=path: self._open_qcx(p))
        row.bind("<space>",  lambda e, p=path: self._open_qcx(p))
        row.bind("<FocusIn>",  lambda e: _ring(True))
        row.bind("<FocusOut>", lambda e: _ring(False))
        row.bind("<Enter>", lambda e: row.config(highlightbackground=C["surface3"])
                 if row.focus_get() is not row else None)
        row.bind("<Leave>", lambda e: row.config(highlightbackground=C["border"])
                 if row.focus_get() is not row else None)

    # ── Navigation ────────────────────────────────────────────────────────────

    def _safe_open_wizard(self, build_wizard):
        """Withdraw the launcher, construct a wizard, recover on failure.

        Previously the launcher called self.withdraw() *before* the wizard's
        import/constructor ran.  If construction raised (missing optional
        dependency, disk error, etc.), the launcher stayed hidden and the
        user saw a running process with no visible window.  This wrapper
        re-shows the launcher and surfaces the error in a dialog so the
        user can recover without force-quitting.
        """
        from tkinter import messagebox
        self.withdraw()
        try:
            build_wizard()
        except Exception as exc:
            self.deiconify()
            messagebox.showerror(
                "Cannot open window",
                f"Something went wrong opening that screen.\n\n{friendly_error(exc)}",
                parent=self,
            )

    def _remember_mode(self, mode: str):
        AppPrefs.set("last_mode", mode)

    def _open_volumes(self, volume_path: str | None = None):
        self._remember_mode("volumes")
        cx = self.winfo_x() + self.winfo_width() // 2
        cy = self.winfo_y() + self.winfo_height() // 2
        def _build():
            from quantacrypt.ui.volume_manager import VolumeManagerApp
            VolumeManagerApp(
                self.master, on_close=self.deiconify, center_at=(cx, cy),
                volume_path=volume_path,
            )
        self._safe_open_wizard(_build)

    def _open_encryptor(self):
        self._remember_mode("encrypt")
        cx = self.winfo_x() + self.winfo_width() // 2
        cy = self.winfo_y() + self.winfo_height() // 2
        def _build():
            from quantacrypt.ui.encryptor import EncryptorApp
            EncryptorApp(self.master, on_close=self.deiconify, center_at=(cx, cy))
        self._safe_open_wizard(_build)

    def _open_decryptor(self):
        """Trigger a file picker immediately so the Decrypt card does what it says.
        Only navigate to the decryptor if the user actually picks a file; if they
        cancel the dialog we stay on the launcher."""
        from tkinter import filedialog
        from quantacrypt.ui.decryptor import load_pkg
        path = filedialog.askopenfilename(
            title="Open encrypted file",
            filetypes=[("QuantaCrypt", "*.qcx"), ("All files", "*")])
        if not path:
            return  # user cancelled — stay on launcher
        try:
            pkg = load_pkg(path)
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror(
                "Cannot open file",
                f"{os.path.basename(path)}\n\n{friendly_error(e)}",
                parent=self)
            return
        self._remember_mode("decrypt")
        cx = self.winfo_x() + self.winfo_width() // 2
        cy = self.winfo_y() + self.winfo_height() // 2
        def _build():
            from quantacrypt.ui.decryptor import DecryptorApp
            DecryptorApp(self.master, payload=pkg, qcx_path=path, on_close=self._on_wizard_close, center_at=(cx, cy))
        self._safe_open_wizard(_build)

    def _on_wizard_close(self):
        """Re-show the launcher and refresh the Recent list (a decrypt may
        have added an entry)."""
        self.deiconify()
        try:
            self._build_recent()
        except Exception:
            pass

    def _open_qcx(self, path):
        """Open a specific .qcx file directly in the decryptor."""
        from quantacrypt.ui.decryptor import DecryptorApp, load_pkg  # noqa: E401
        try:
            pkg = load_pkg(path)
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror(
                "Cannot open file",
                f"{os.path.basename(path)}\n\n{friendly_error(e)}",
                parent=self)
            return
        self._remember_mode("decrypt")
        cx = self.winfo_x() + self.winfo_width() // 2
        cy = self.winfo_y() + self.winfo_height() // 2
        def _build():
            DecryptorApp(self.master, payload=pkg, qcx_path=path, on_close=self._on_wizard_close, center_at=(cx, cy))
        self._safe_open_wizard(_build)

    def _inspect_file(self):
        """Open a .qcx file and show its metadata without entering credentials."""
        from tkinter import filedialog, messagebox
        from quantacrypt.ui.decryptor import load_pkg
        path = filedialog.askopenfilename(
            title="Inspect encrypted file",
            filetypes=[("QuantaCrypt", "*.qcx"), ("All files", "*")])
        if not path: return
        try:
            pkg = load_pkg(path)
        except Exception as e:
            messagebox.showerror(
                "Cannot read file",
                f"{os.path.basename(path)}\n\n{friendly_error(e)}",
                parent=self)
            return
        meta = pkg["meta"]
        # Build a summary dialog
        win = tk.Toplevel(self)
        win.title(f"File info — {os.path.basename(path)}")
        win.configure(bg=C["bg"])
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()
        P = SP["xl"]
        tk.Label(win, text="File information", font=F["heading"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w", padx=P, pady=(SP["l"], SP["m"]))
        inner = card(win, padx=SP["m"], pady=SP["xs"])
        inner.outer.pack(fill="x", padx=P, pady=(0, SP["s"]))
        if meta.get("mode") == "single":
            mode_str = "Password"
        else:
            mode_str = (f"Split key: any {meta.get('threshold')} of "
                        f"{meta.get('total')} shares open it")
        rows = [
            ("File",       os.path.basename(path)),
            ("Size",       fmt_size(os.path.getsize(path))),
            ("Format",     f"v{meta.get('version', '?')}"),
            ("Unlocks with", mode_str),
            ("Encryption", "Strong, and safe against future quantum computers "
                           "(AES-256-GCM + ML-KEM)"),
        ]
        if meta.get("mode") == "single" and "argon_salt" in meta:
            rows.append(("Password", "Slow-hashed so guessing is expensive (Argon2id)"))
        if meta.get("payload_offset"):
            rows.append(("Portable", "Includes its own decryptor"))
        for lbl, val in rows:
            kv_row(inner, lbl, val, label_width=12, wraplength=320)
        # Path
        tk.Label(win, text=path, font=F["small"], bg=C["bg"], fg=C["text3"],
                 wraplength=380, justify="left").pack(anchor="w", padx=P, pady=(0, SP["xs"]))
        note = tk.Label(win,
                        text="The original filename, size and date are inside the "
                             "encrypted data and appear only after decryption.",
                        font=F["small"], bg=C["bg"], fg=C["text3"],
                        wraplength=380, justify="left")
        note.pack(anchor="w", padx=P, pady=(0, SP["m"]))
        btn_row = tk.Frame(win, bg=C["bg"]); btn_row.pack(fill="x", padx=P, pady=(0, SP["l"]))
        FlatButton(btn_row, f"Decrypt this file {ICON['arrow']}",
                   lambda: (win.destroy(), self._open_qcx(path)),
                   primary=True, small=True).pack(side="left")
        close_btn = FlatButton(btn_row, "Close", win.destroy,
                               primary=False, small=True)
        close_btn.pack(side="left", padx=(SP["s"], 0))
        win.bind("<Escape>", lambda e: win.destroy())
        close_btn.focus_set()
        # Centre over launcher
        win.update_idletasks()
        lx, ly = self.winfo_x(), self.winfo_y()
        lw, lh = self.winfo_width(), self.winfo_height()
        ww, wh = win.winfo_width(), win.winfo_height()
        win.geometry(f"+{lx+(lw-ww)//2}+{ly+(lh-wh)//2}")


if __name__ == "__main__":
    # Standalone launch — create a hidden root (same pattern as quantacrypt.py)
    root = tk.Tk()
    root.withdraw()
    LauncherApp(root)
    root.mainloop()
