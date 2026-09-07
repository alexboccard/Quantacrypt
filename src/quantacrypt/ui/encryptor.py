#!/usr/bin/env python3
"""QuantaCrypt Encryptor — encryption GUI with password and Shamir modes."""
import os
import re
import subprocess
import sys
import threading

import tkinter as tk
from tkinter import filedialog, messagebox

from quantacrypt.core import crypto as cc
from quantacrypt.core import package as pkg
from quantacrypt.core.package import (  # noqa: F401  (re-exported for tests)
    folder_stats as _folder_stats,
    batch_output_paths as _batch_output_paths,
    zip_folder as _zip_folder,
)
from quantacrypt.ui.shared import (
    C, F, SP, ICON, REVEAL_LABEL,
    accel, bind_shortcut, confirm, friendly_error, reveal_path, safe_after,
    write_new_private_file,
    styled_entry, bind_context_menu, fmt_size, rule, section_label,
    FlatButton, SegmentedControl, StagedProgressBar,
    PasswordStrengthBar, FileCard, WizardSteps, ClipboardTimer,
    copy_secret, notify,
)

# Friendly stage names + relative weights.  The list shown to the user is
# built PER RUN (see _stages_for): "Compressing folder" only for folders,
# "Securing password" only in password mode.
STAGES = [
    ("Compressing folder",    0.10),
    ("Securing password",     0.50),
    ("Generating protection", 0.13),
    ("Locking key",           0.04),
    ("Encrypting file",       0.18),
    ("Saving",                0.05),
]
# Indices for stages that carry semantic meaning in the code
STAGE_COMPRESS = 0
STAGE_ARGON    = 1
STAGE_KEM      = 2
STAGE_ENCKEY   = 3
STAGE_PAYLOAD  = 4
STAGE_WRITE    = 5

# Most-specific keyword first: "Encrypting Kyber private key under master
# key" must land on Locking key, not on the Kyber/master-key entries.
_STAGE_KEYWORDS = [
    ("private key",  STAGE_ENCKEY),
    ("compressing",  STAGE_COMPRESS),
    ("argon2",       STAGE_ARGON),
    ("keypair",      STAGE_KEM),
    ("encapsulating", STAGE_KEM),
    ("master key",   STAGE_KEM),
    ("payload",      STAGE_PAYLOAD),
    ("writing",      STAGE_WRITE),
]

def _find_stage(msg):
    """Map a raw core progress string to a semantic STAGE_* index (or None)."""
    low = (msg or "").lower()
    for kw, idx in _STAGE_KEYWORDS:
        if kw in low:
            return idx
    return None

def _stage_label(idx, msg=None):
    """Friendly stage name plus any NN% the core reported — never the raw string."""
    label = STAGES[idx][0]
    m = re.search(r"(\d+)%", msg or "")
    return f"{label}  {m.group(1)}%" if m else label

def _reveal(path, open_file=False):
    """Show the file in the file manager (or open it).  Returns False when
    no handler could be launched so callers can say so in the status line."""
    if not open_file:
        return reveal_path(path)
    try:
        if sys.platform == "darwin":
            # "--": a self-typed output name like -foo.qcx is not a flag.
            subprocess.Popen(["open", "--", path])
        elif sys.platform == "win32":
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            # xdg-open rejects "--"; an absolute path cannot start with a dash.
            subprocess.Popen(["xdg-open", os.path.abspath(path)])
        return True
    except Exception:
        return False


def _mnemonics_for(shares, k, known=None):
    """One mnemonic per share (None where a code can't be decoded).  The
    threshold is injected because decode_share carries none — without it
    every mnemonic would encode threshold=0.  ``known`` is the list the
    core already returned with the codes (package.shares_with_mnemonics);
    when it lines up with ``shares`` it is used as-is."""
    if known and len(known) == len(shares) and all(known):
        return list(known)
    out = []
    for s in shares:
        try:
            out.append(cc.share_to_mnemonic({**cc.decode_share(s), "threshold": k}))
        except Exception:
            out.append(None)
    return out


def _root_of(widget):
    """The Tk root above ``widget`` — the owner for timers that must outlive
    the wizard window (clipboard auto-clear)."""
    try:
        top = widget.winfo_toplevel()
        return getattr(top, "master", None) or top
    except Exception:
        return widget


def _share_file_names(folder, stem, n):
    """Paths for one run of individual share files.  Collision handling is
    per RUN (as the native app does): if any ``<stem>.share-i-of-n.txt``
    exists (or is a dangling symlink), the whole set moves to
    ``<stem>_N.share-…`` so one run never mixes two stems and a recipient
    can match "share-2-of-3" to its set.  Returns ``(paths, renamed)``."""
    import errno
    for suffix in range(1, 100):
        s = stem if suffix == 1 else f"{stem}_{suffix}"
        names = [os.path.join(folder, f"{s}.share-{i}-of-{n}.txt") for i in range(1, n + 1)]
        if not any(os.path.lexists(p) for p in names):
            return names, suffix > 1
    raise FileExistsError(
        errno.EEXIST,
        f"99 sets of share files named {stem}.share-… already exist here. "
        "choose another folder", folder)


class ShareCard(tk.Frame):
    def __init__(self, parent, idx, raw, mnemonic=None, **kw):
        super().__init__(parent, bg=C["surface"],
                         highlightbackground=C["border"], highlightthickness=1, **kw)
        self._raw=raw; self._mn=mnemonic
        self._use_mn=bool(mnemonic)  # default: show mnemonic when available
        hdr=tk.Frame(self,bg=C["surface"])
        hdr.pack(fill="x",padx=SP["l"],pady=(SP["m"],SP["xs"]))
        tk.Label(hdr,text=f"Share {idx}",font=F["body_b"],
                 bg=C["surface"],fg=C["text"]).pack(side="left")
        if mnemonic:
            # Prominent toggle button — much more discoverable than a tiny checkbox
            self._fmt_btn=FlatButton(hdr,"Switch to code",self._toggle_fmt,
                                     primary=False,small=True)
            self._fmt_btn.pack(side="right")
        self._txt=tk.Text(self,font=F["mono_s"],bg=C["surface2"],fg=C["text2"],
                          relief="flat",bd=0,highlightthickness=0,wrap="word",
                          selectbackground=C["accent_dim"])
        bind_context_menu(self._txt)
        # ⌘C and the context menu's Copy both raise <<Copy>>; routed here
        # they get the concealed marker and the countdown like the button,
        # instead of Tk's stock append that a clipboard manager keeps.
        self._txt.bind("<<Copy>>", self._copy_event)
        self._txt.pack(fill="x",padx=SP["l"],pady=(0,SP["xs"]))
        # The Text sizes itself to its content (see _refresh); the outer
        # canvas owns the wheel, so it must never need to scroll internally.
        self._txt.bind("<Configure>", lambda e: self._fit_height())
        self._refresh()
        btn_row = tk.Frame(self, bg=C["surface"]); btn_row.pack(fill="x", padx=SP["l"], pady=(0,SP["s"]))
        self._copy_btn = FlatButton(btn_row,"Copy",self._copy,primary=False,small=True)
        self._copy_btn.pack(side="left")
        # Clipboard auto-clear countdown label
        self._clip_lbl = tk.Label(btn_row, text="", font=F["small"],
                                   bg=C["surface"], fg=C["text3"])
        self._clip_lbl.pack(side="left", padx=(SP["s"],0))
        # Owned by the ROOT, not the card: a pending after() dies with its
        # owner, and the wizard is routinely destroyed inside the 60 s
        # ("Test decryption →", Home) — the clipboard must still clear.
        self._clip_timer = ClipboardTimer(_root_of(self), self._clip_lbl)

    def _current(self):
        return self._mn if (self._use_mn and self._mn) else self._raw

    def _toggle_fmt(self):
        self._use_mn = not self._use_mn
        self._fmt_btn.set_text("Switch to words" if not self._use_mn else "Switch to code")
        self._refresh()

    def _refresh(self):
        self._txt.config(state="normal")
        self._txt.delete("1.0","end"); self._txt.insert("1.0",self._current())
        self._txt.config(state="disabled")
        self._fit_height()

    def _fit_height(self):
        """Size the Text to its wrapped line count so a 6-line mnemonic is
        never clipped behind a fixed height."""
        try:
            n = self._txt.count("1.0", "end", "displaylines")
            n = n[0] if isinstance(n, (tuple, list)) else n
            self._txt.config(height=max(2, min(10, int(n or 0))))
        except Exception:
            self._txt.config(height=6 if (self._use_mn and self._mn) else 2)

    def _copy(self):
        try:
            # copy() marks the share concealed so clipboard managers skip it,
            # and arms the 60-second auto-clear countdown.
            self._clip_timer.copy(self, self._current())
            self._copy_btn.set_text(f"{ICON['ok']} Copied")
            self.after(1500, lambda: self._copy_btn.set_text("Copy") if self.winfo_exists() else None)
        except Exception:
            self._copy_btn.set_text(f"{ICON['warn']} Failed")
            self.after(2000, lambda: self._copy_btn.set_text("Copy") if self.winfo_exists() else None)

    def _copy_event(self, _event=None):
        self._copy()
        return "break"

    def mark_saved(self):
        """Visually indicate this share has been written to a file."""
        try:
            # Only the label goes: a share copied moments before the save is
            # still on the clipboard and the wipe must stay armed for it.
            self._clip_timer.detach_label()
            self._copy_btn.enable(False)
            self._copy_btn.set_text(f"{ICON['ok']} Saved")
            self.config(highlightbackground=C["success"])
        except Exception: pass


# DnD support — works when the root Tk was created as TkinterDnD.Tk
try:
    from tkinterdnd2 import DND_FILES as _DND_FILES
except ImportError:
    _DND_FILES = None


class EncryptorApp(tk.Toplevel):
    STEPS = ["Source", "Protection", "Secret", "Output", "Encrypt"]
    _P    = SP["xl"]   # Single class-level padding constant

    def __init__(self, master=None, on_close=None, center_at=None):
        super().__init__(master)
        self.title("QuantaCrypt · Encrypt")
        self.configure(bg=C["bg"])
        self.resizable(True, True)
        self.geometry("620x780")
        self.minsize(560, 560)
        self._path=None; self._is_folder=False; self._batch_paths=[]; self._mode=tk.StringVar(value="single")
        self._n=tk.IntVar(value=3); self._k=tk.IntVar(value=2)
        self._pw1v=tk.StringVar(); self._pw2v=tk.StringVar()
        self._embed_dec=tk.BooleanVar(value=False)
        # Shamir k/n frozen at encryption start.  The spinboxes stay live
        # widgets after _freeze()/_thaw(), so re-reading them when writing
        # mnemonics/share files would bake post-start drift into recovery
        # material the decryptor then rejects.
        self._result_k: int | None = None
        self._result_n: int | None = None
        # Set of tokens (one per encrypted file with unsaved Shamir shares;
        # "__single__" in single-file mode).  Empty set = safe to leave.
        # A set, not a bool: in batch mode each file has its OWN shares,
        # and saving one file's must not disarm the guard for the rest.
        self._shares_pending: set = set()
        self._pending_shares=[]
        self._scroll_job=None  # Track pending scroll so _reset can cancel it
        self._busy=False; self._on_close=on_close
        # Cancel support: set by the Cancel button on the progress UI; the
        # crypto stream checks this at chunk boundaries and raises
        # CancelledOperation so the worker can delete the partial output.
        import threading as _th
        self._cancel_event = _th.Event()
        self._out_auto=False  # True when output path was auto-generated
        # True while a result card is showing: the wizard stays "complete"
        # even though _done clears the password fields (which would
        # otherwise recompute the highlight back to step 1).
        self._show_done=False
        # Always wire WM_DELETE_WINDOW through _close so share guard fires
        self.protocol("WM_DELETE_WINDOW", self._close)
        self._build()
        self._center(center_at=center_at)
        self.update()  # macOS: force canvas embedded-window Configure event so form renders
        # Register DnD (only works when base class is TkinterDnD.Tk).  The
        # card only promises "drag & drop" once registration succeeded.
        self._dnd_ok = False
        if _DND_FILES:
            try:
                self.drop_target_register(_DND_FILES)
                self.dnd_bind("<<Drop>>", self._on_drop)
                self._dnd_ok = True
            except Exception:
                pass
        self._file_card.set_drop_supported(
            self._dnd_ok, "Click anywhere · or drag & drop", "Click anywhere")
        # ⌘O / Ctrl+O opens the picker for the current source type
        def _open_shortcut():
            if self._busy:
                self._flash_status("Busy. Please wait for encryption to finish")
            elif self._src_type.get() == "batch":
                self._on_batch_select()
            else:
                self._file_card._pick()
        bind_shortcut(self, "o", _open_shortcut)
        # ⌘↵ / Ctrl+↵ starts encryption (shows busy message if already running)
        def _submit_shortcut():
            if self._busy:
                self._flash_status("Busy. Please wait for encryption to finish")
            else:
                self._start()
        bind_shortcut(self, "Return", _submit_shortcut)
        # Escape: cancel a running job, guard a half-filled form, else close.
        self.bind("<Escape>", lambda e: self._on_escape())

    # ── Status line helpers ───────────────────────────────────────────────
    # One label, two voices: neutral status in grey, errors in red.
    def _set_status(self, msg):
        self._err.config(text=msg, fg=C["text3"])

    def _set_error(self, msg):
        self._err.config(text=msg, fg=C["error"])

    def _flash_status(self, msg, ms=2000):
        self._set_status(msg)
        self.after(ms, lambda: self._set_status("")
                   if self._err.cget("text") == msg else None)

    def _check_shares_saved(self):
        """Return True if safe to proceed; prompt if shares may be unsaved."""
        if not self._shares_pending:
            return True
        # Name the file(s) that become unopenable.  Kept getattr-safe: the
        # guard is unit-tested on a bare namespace carrying only the set.
        names = sorted(os.path.basename(t) for t in self._shares_pending
                       if t != "__single__")
        if "__single__" in self._shares_pending:
            out = getattr(self, "_out", None)
            cur = out.get().strip() if out is not None else ""
            names.insert(0, os.path.basename(cur) if cur else "the encrypted file")
        shown = ", ".join(names[:3]) + (f" and {len(names)-3} more" if len(names) > 3 else "")
        # Parented so it can't open behind the wizard (the unit test drives
        # this on a bare namespace, hence the guard).
        opts = {"parent": self} if isinstance(self, tk.Misc) else {}
        if not messagebox.askyesno(
                "Shares not saved",
                f"Save the shares first. Without them, {shown} can never be "
                f"opened again.\n\nLeave and discard the shares?",
                icon="warning", default="no", **opts):
            return False
        return True

    def _has_unsaved_input(self):
        """True while the form holds something the user typed or picked and
        no result has been produced yet (results have their own guard)."""
        if self._results.winfo_children():
            return False
        return bool(self._path or self._batch_paths
                    or self._pw1v.get() or self._pw2v.get())

    def _on_escape(self):
        if self._busy:
            self._request_cancel()
            return
        if not self._confirm_discard_form():
            return
        self._close()

    def _confirm_discard_form(self) -> bool:
        return not self._has_unsaved_input() or confirm(
            self, "Discard this form?",
            "The file, password and output you've entered here will be lost.",
            yes="Discard", no="Keep editing", danger=True)

    def can_quit(self) -> bool:
        """The Quit Apple event's guard (``__main__._register_quit``): the
        same refusals the close button makes, without destroying anything.
        The half-typed-form prompt lives on Escape only, so ⌘Q matches the
        close button rather than asking where it would not (run 20 F-012)."""
        if self._busy:
            self._flash_status("Encryption in progress. Please wait until it finishes", 3000)
            return False
        return self._check_shares_saved()

    def _close(self):
        if self._busy:
            self._flash_status("Encryption in progress. Please wait until it finishes", 3000)
            return
        if not self._check_shares_saved(): return
        self.destroy()
        if self._on_close:
            self._on_close()
        else:
            self.master.destroy()  # no launcher — quit app

    def _center(self, center_at=None):
        self.update_idletasks()
        w, h = self.winfo_width(), self.winfo_height()
        if center_at:
            cx, cy = center_at
        else:
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            cx, cy = sw // 2, sh // 2
        x = max(0, cx - w // 2)
        y = max(0, cy - h // 2)
        self.geometry(f"+{x}+{y}")

    def _on_drop(self, event):
        """Handle drag-and-drop: one folder → folder mode, one file → file
        mode, several files (or any drop while in batch mode) → batch."""
        if self._busy:
            self._flash_status("Encryption in progress. Please wait until it finishes", 3000)
            return
        try:
            paths = [p for p in self.tk.splitlist(event.data) if p]
        except Exception:
            raw = event.data.strip()
            if raw.startswith("{") and raw.endswith("}"): raw = raw[1:-1]
            paths = raw.split("} {")
        files = [p for p in paths if os.path.isfile(p)]
        dirs  = [p for p in paths if os.path.isdir(p)]
        if len(files) > 1 or (files and self._src_type.get() == "batch"):
            if not self._confirm_replace_batch(): return
            self._set_batch_paths(files)
            self._src_type.set("batch")
            self._build_batch_ui()
            self._refresh_step()
        elif dirs:
            if len(dirs) > 1:
                self._flash_status(f"One folder at a time — using {os.path.basename(dirs[0].rstrip('/'))}", 3000)
            # Auto-switch toggle to folder mode and load
            self._src_type.set("folder")
            self._on_folder(dirs[0])
        elif files:
            self._src_type.set("file")
            self._file_card.load(files[0])
            self._on_file(files[0])

    def _build(self):
        P = self._P  # Local alias so all padx=P in _build use class constant
        hdr=tk.Frame(self,bg=C["bg"])
        hdr.pack(fill="x",padx=P,pady=(SP["l"],0))
        tk.Label(hdr,text="QuantaCrypt",font=F["display"],bg=C["bg"],fg=C["text"]).pack(side="left")
        tk.Label(hdr,text="Encrypt",font=F["heading"],bg=C["bg"],fg=C["text3"]).pack(side="left",padx=(SP["s"],0),pady=SP["xs"])
        if self._on_close:
            FlatButton(hdr,f"{ICON['back']} Home",self._close,primary=False,small=True).pack(side="right")
        self._wiz=WizardSteps(self,self.STEPS)
        self._wiz.pack(fill="x",padx=P,pady=(SP["m"],0))
        rule(self,pady=0)

        outer=tk.Frame(self,bg=C["bg"]); outer.pack(fill="both",expand=True)
        cv=tk.Canvas(outer,bg=C["bg"],bd=0,highlightthickness=0)
        vsb=tk.Scrollbar(outer,orient="vertical",command=cv.yview)
        cv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right",fill="y"); cv.pack(side="left",fill="both",expand=True)
        b=self._body=tk.Frame(cv,bg=C["bg"])
        self._cv=cv  # store for scroll-to-top on reset
        wid=cv.create_window((0,0),window=b,anchor="nw")
        b.bind("<Configure>",lambda e:cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>",lambda e:cv.itemconfig(wid,width=e.width))
        # Focus-aware scroll: only scroll this canvas when focus is not in a Toplevel dropdown
        def _scroll(delta):
            fw = self.focus_get()
            if fw and fw.winfo_toplevel() is not self: return
            cv.yview_scroll(delta, "units")
        # Bound on THIS toplevel (every descendant carries it in its bindtags),
        # not bind_all: a root-wide binding outlives the window and the two
        # wizards would replace each other's handler.
        self.bind("<MouseWheel>", lambda e: _scroll(int(-e.delta)))

        # 1. File/Folder/Batch picker
        section_label(b,"1  SOURCE",padx=P)
        self._src_type = tk.StringVar(value="file")
        self._src_toggle = SegmentedControl(b,
            [("file","Single File"),("folder","Entire Folder"),("batch","Multiple Files")],
            self._src_type)
        self._src_toggle.pack(fill="x",padx=P,pady=(0,SP["s"]))
        self._src_type.trace_add("write", self._on_src_type)
        self._file_card=FileCard(b, self._on_file, on_folder=self._on_folder,
                                 prompt="Select a file to encrypt",
                                 sub="Click anywhere")
        self._file_card.pack(fill="x",padx=P)
        # Batch file list (shown only in batch mode)
        self._batch_frame = tk.Frame(b, bg=C["bg"])
        # (packed/unpacked by _on_src_type)

        # 2. Mode
        section_label(b,"2  PROTECTION",padx=P)
        self._mode_w=SegmentedControl(b,[("single","Single Password"),("shamir","Split Between People")],
                         self._mode)
        self._mode_w.pack(fill="x",padx=P)
        self._mode_hint=tk.Label(b,text="",font=F["caption"],bg=C["bg"],fg=C["text3"],
                                  anchor="w",wraplength=500)
        self._mode_hint.pack(fill="x",padx=P,pady=(SP["xs"],0))
        self._mode.trace_add("write",self._on_mode)

        # 3. Secret — heading is relabelled "3  SHARES" in split mode
        self._secret_lbl = self._section(b, "3  PASSWORD")
        self._sec_wrap=tk.Frame(b,bg=C["bg"]); self._sec_wrap.pack(fill="x",padx=P)
        self._pw_panel=tk.Frame(self._sec_wrap,bg=C["bg"])
        tk.Label(self._pw_panel,text="Password",font=F["caption"],bg=C["bg"],
                 fg=C["text3"]).pack(anchor="w",pady=(0,SP["xs"]))

        # Password row with per-field show/hide toggle
        pw1_row=tk.Frame(self._pw_panel,bg=C["bg"]); pw1_row.pack(fill="x",pady=(0,SP["xs"]))
        self._pw1=styled_entry(pw1_row,textvariable=self._pw1v,show="•")
        self._pw1.pack(side="left",fill="x",expand=True,ipady=SP["s"],ipadx=SP["s"])
        self._eye1_btn=FlatButton(pw1_row,"Show",lambda:self._toggle_pw(1),primary=False,small=True)
        self._eye1_btn.pack(side="left",padx=(SP["xs"],0))
        self._pw1.bind("<Return>", lambda e: self._pw2.focus())

        self._strength=PasswordStrengthBar(self._pw_panel,self._pw1v)
        self._strength.pack(fill="x",pady=(0,SP["s"]))
        tk.Label(self._pw_panel,text="Confirm password",font=F["caption"],
                 bg=C["bg"],fg=C["text3"]).pack(anchor="w",pady=(0,SP["xs"]))

        pw2_row=tk.Frame(self._pw_panel,bg=C["bg"]); pw2_row.pack(fill="x")
        self._pw2=styled_entry(pw2_row,textvariable=self._pw2v,show="•")
        self._pw2.pack(side="left",fill="x",expand=True,ipady=SP["s"],ipadx=SP["s"])
        self._eye2_btn=FlatButton(pw2_row,"Show",lambda:self._toggle_pw(2),primary=False,small=True)
        self._eye2_btn.pack(side="left",padx=(SP["xs"],0))
        self._pw2.bind("<Return>", lambda e: self._start())

        self._match_lbl=tk.Label(self._pw_panel,text="",font=F["caption"],
                                  bg=C["bg"],fg=C["text3"])
        self._match_lbl.pack(anchor="w",pady=(SP["xs"],0))
        self._pw1v.trace_add("write", self._check_match)
        self._pw2v.trace_add("write",self._check_match)

        self._sh_panel=tk.Frame(self._sec_wrap,bg=C["bg"])
        self._build_shamir(self._sh_panel)

        # 4. Output — wrapped in _out_section so batch mode can hide it
        self._out_section = tk.Frame(b, bg=C["bg"])
        self._out_section.pack(fill="x", padx=0)
        section_label(self._out_section,"4  OUTPUT FILE",padx=P)
        out_row=tk.Frame(self._out_section,bg=C["bg"]); out_row.pack(fill="x",padx=P)
        self._out=styled_entry(out_row)
        self._out.pack(side="left",fill="x",expand=True,ipady=SP["s"],ipadx=SP["s"])
        self._browse_btn = FlatButton(out_row,"Browse…",self._browse_out,primary=False,small=True)
        self._browse_btn.pack(side="left",padx=(SP["s"],0))
        # Any manual edit marks the path as user-supplied (don't auto-replace)
        self._out.bind("<Key>", lambda e: setattr(self, "_out_auto", False)
                       if e.keysym not in ("Return", "Tab") else None)
        self._out.bind("<KeyRelease>", lambda e: self._refresh_step())
        self._out.bind("<Return>", lambda e: self._start())
        self._out_hint = tk.Label(self._out_section,
            text=".qcx is QuantaCrypt's encrypted format, safe to store or share",
            font=F["small"], bg=C["bg"], fg=C["text3"], anchor="w")
        self._out_hint.pack(fill="x", padx=P, pady=(SP["xs"], 0))

        # Embed decryptor — only shown when a usable standalone binary
        # exists (never in frozen builds; see _find_dec).  Not a numbered
        # wizard step: it is an optional extra, not part of the flow.
        if self._find_dec():
            section_label(b,"PORTABLE FILE",padx=P)
            embed_row=tk.Frame(b,bg=C["bg"]); embed_row.pack(fill="x",padx=P)
            self._embed_chk=tk.Checkbutton(
                embed_row, variable=self._embed_dec,
                text="Embed decryptor so recipients can run the .qcx file directly",
                font=F["body"], bg=C["bg"], fg=C["text"],
                selectcolor=C["surface2"], activebackground=C["bg"],
                activeforeground=C["text"], relief="flat", bd=0,
                cursor="hand2", command=self._on_embed_toggle,
            )
            self._embed_chk.pack(anchor="w")
            self._embed_hint=tk.Label(embed_row,text="",
                font=F["caption"],bg=C["bg"],fg=C["text3"],anchor="w",justify="left")
            self._embed_hint.pack(fill="x",pady=(SP["xs"],0))
            self._on_embed_toggle()
        else:
            # Running from source without a built binary — skip this section entirely
            self._embed_hint=tk.Label(b)  # dummy so _on_embed_toggle refs don't crash

        self._act_rule = rule(b,pady=SP["l"],padx=P)
        act=tk.Frame(b,bg=C["bg"]); act.pack(fill="x",padx=P,pady=(0,SP["xs"]))
        self._btn=FlatButton(act,f"Encrypt File {ICON['arrow']}",self._start)
        self._btn.pack(side="left")
        self._on_src_type()   # set initial button label
        # Status/error label on its own row so long messages wrap cleanly
        self._err=tk.Label(b,text="",font=F["caption"],bg=C["bg"],fg=C["error"],
                           anchor="w",justify="left",wraplength=490)
        self._err.pack(fill="x",padx=P,pady=(0,SP["s"]))

        # Placeholder bar; every run builds its own (see _new_prog) so the
        # stage dots match what will actually happen.
        self._run_stages = []
        self._stage_map = {}
        self._prog=StagedProgressBar(b,[(n,w) for n,w in STAGES])
        # Cancel button row shown alongside the progress bar while busy.
        self._cancel_row = tk.Frame(b, bg=C["bg"])
        self._cancel_btn = FlatButton(
            self._cancel_row, "Cancel", self._request_cancel,
            primary=False, small=True,
        )
        self._cancel_btn.pack(side="right")
        self._results=tk.Frame(b,bg=C["bg"]); self._results.pack(fill="x",padx=P,pady=(0,SP["m"]))
        # Keyboard shortcut hint
        tk.Label(b, text=f"{accel('O')}  Open file  ·  {accel('↵')}  Encrypt",
                 font=F["small"], bg=C["bg"], fg=C["text3"]).pack(pady=(0,SP["l"]))
        self._on_mode()

    @staticmethod
    def _section(parent, text):
        """Section heading; returns its text Label so the heading can be
        relabelled later (PASSWORD ↔ SHARES)."""
        return section_label(parent, text, padx=EncryptorApp._P)

    # Per-field show/hide toggle with text button
    def _toggle_pw(self, field=0):
        if field == 1:
            vis = self._pw1.cget("show") == "•"
            self._pw1.config(show="" if vis else "•")
            self._eye1_btn.set_text("Hide" if vis else "Show")
        elif field == 2:
            vis = self._pw2.cget("show") == "•"
            self._pw2.config(show="" if vis else "•")
            self._eye2_btn.set_text("Hide" if vis else "Show")

    def _on_embed_toggle(self, *_):
        dec = self._find_dec()
        if self._embed_dec.get():
            if dec:
                try:
                    dec_sz = fmt_size(os.path.getsize(dec))
                except OSError:
                    dec_sz = "some bytes"
                self._embed_hint.config(
                    text=f"The .qcx will be {dec_sz} larger. "
                         f"Recipients on macOS can run it directly, with no separate app needed.",
                    fg=C["text3"])
            else:
                self._embed_dec.set(False)
                self._embed_hint.config(text="Decryptor binary not found. Build with: python3 build.py",
                                        fg=C["error"])
        else:
            # Always show hint so user understands the checkbox even without a file
            self._embed_hint.config(text="Recipients will need the quantacrypt app to open this file.",
                                    fg=C["text3"])

    def _build_shamir(self,parent):
        # Header row: hint + collapsible ? help button
        hdr=tk.Frame(parent,bg=C["bg"]); hdr.pack(fill="x",pady=(0,SP["xs"]))
        tk.Label(hdr,text="Choose how many people hold a share, and how many are needed to unlock.",
            font=F["caption"],bg=C["bg"],fg=C["text3"]).pack(side="left")
        self._shamir_help_visible=False
        # A real button: reachable with Tab, fires on Return/space
        self._help_btn=FlatButton(hdr,"?",self._toggle_shamir_help,primary=False,small=True)
        self._help_btn.pack(side="left",padx=(SP["s"],0))

        # Help box — packed here so it sits between header and grid in document order.
        # Starts hidden; _toggle_shamir_help reveals/hides it.
        self._shamir_help=tk.Frame(parent,bg=C["surface"],
                                   highlightbackground=C["border"],highlightthickness=1)
        tk.Label(self._shamir_help,
            text="Imagine a vault that needs multiple keys to open:\n\n"
                 "• You give each person a unique share (like a unique key)\n"
                 "• No single person can open the file alone\n"
                 "• Only when enough people combine their shares can the file be unlocked\n\n"
                 "Example: Give 3 family members a share, require any 2 to unlock. "
                 "great for wills, team backups, or shared secrets.",
            font=F["caption"],bg=C["surface"],fg=C["text2"],
            justify="left",wraplength=480,anchor="w").pack(padx=SP["m"],pady=SP["s"],fill="x")
        # Don't pack yet — _toggle_shamir_help will do it when needed

        # Preset buttons for the three most common Shamir configurations.
        # The one matching the current k/n is tinted (see _refresh_presets).
        preset_row = tk.Frame(parent, bg=C["bg"])
        preset_row.pack(fill="x", pady=(SP["xs"],SP["s"]))
        tk.Label(preset_row, text="Quick presets:", font=F["caption"],
                 bg=C["bg"], fg=C["text3"]).pack(side="left", padx=(0,SP["s"]))
        self._preset_btns = {}
        for lbl,(pn,pk) in [("2-of-3",(3,2)),("3-of-5",(5,3)),("3-of-7",(7,3))]:
            btn = FlatButton(preset_row, lbl,
                             lambda n=pn,k=pk: (self._n.set(n), self._k.set(k)),
                             primary=False, small=True)
            btn.pack(side="left", padx=(0,SP["s"]))
            self._preset_btns[(pn,pk)] = btn
        tk.Label(preset_row, text="or set below", font=F["caption"],
                 bg=C["bg"], fg=C["text3"]).pack(side="left", padx=(SP["s"],0))

        self._shamir_grid=tk.Frame(parent,bg=C["bg"])  # stored ref avoids winfo_children()[-1] fragility
        self._shamir_grid.pack(fill="x",pady=(0,0))
        self._shamir_grid.columnconfigure(0,weight=1); self._shamir_grid.columnconfigure(1,weight=1)
        for col,(lbl,var,tip) in enumerate([
            ("Required to unlock",self._k,"Minimum people needed"),
            ("Total people",self._n,"How many shares to create"),
        ]):
            card=tk.Frame(self._shamir_grid,bg=C["surface"],highlightbackground=C["border"],highlightthickness=1)
            card.grid(row=0,column=col,padx=(0 if col==0 else SP["s"],0),sticky="ew")
            tk.Label(card,text=lbl,font=F["caption"],bg=C["surface"],fg=C["text3"]).pack(anchor="w",padx=SP["m"],pady=(SP["s"],SP["xs"]))
            # Wrap Spinbox in a focus-ring Frame so keyboard users get a
            # visible accent outline matching the rest of the form's style.
            sp_wrap = tk.Frame(card, bg=C["surface"],
                               highlightbackground=C["border"], highlightthickness=1)
            sp_wrap.pack(anchor="w", padx=SP["m"], pady=(0,SP["xs"]))
            # Aqua Tk ignores bg/fg on a native Spinbox (renders white), so
            # build one from an Entry plus two step buttons; Up/Down keys step.
            sp = tk.Entry(sp_wrap, textvariable=var, width=3, justify="center",
                          font=F["heading"], bg=C["surface"], fg=C["text"],
                          insertbackground=C["accent_text"], relief="flat", bd=0,
                          highlightthickness=0)
            sp.pack(side="left", ipady=SP["xs"], padx=(SP["xs"], 0))
            def _bump(v=var, d=0):
                try: cur = int(v.get())
                except (tk.TclError, ValueError): cur = 2
                v.set(max(2, min(20, cur + d)))
            FlatButton(sp_wrap, "−", lambda b=_bump: b(d=-1), primary=False, small=True).pack(side="left", padx=(SP["xs"], 0))
            FlatButton(sp_wrap, "+", lambda b=_bump: b(d=1), primary=False, small=True).pack(side="left", padx=(SP["xs"], SP["xs"]))
            sp.bind("<Up>",   lambda e, b=_bump: b(d=1))
            sp.bind("<Down>", lambda e, b=_bump: b(d=-1))
            sp.bind("<FocusIn>",  lambda e, w=sp_wrap: w.config(highlightbackground=C["accent_text"], highlightthickness=2))
            sp.bind("<FocusOut>", lambda e, w=sp_wrap: w.config(highlightbackground=C["border"], highlightthickness=1))
            sp.bind("<Return>", lambda e: self._start())
            tk.Label(card,text=tip,font=F["caption"],bg=C["surface"],fg=C["text3"]).pack(anchor="w",padx=SP["m"],pady=(SP["xs"],SP["s"]))
        # Live summary label showing current threshold interpretation
        self._shamir_summary = tk.Label(parent,
            text=f"Any {self._k.get()} of {self._n.get()} people can unlock the file",
            font=F["caption"], bg=C["bg"], fg=C["accent_text"], anchor="w")
        self._shamir_summary.pack(fill="x", pady=(SP["s"],0))
        self._refresh_presets()
        # Live K≤N clamping: whenever N or K changes, keep K ≤ N
        self._n.trace_add("write", self._clamp_k)
        self._k.trace_add("write", self._clamp_k)

    def _toggle_shamir_help(self):
        self._shamir_help_visible = not self._shamir_help_visible
        if self._shamir_help_visible:
            self._shamir_help.pack(fill="x", pady=(0,SP["s"]), before=self._shamir_grid)
        else:
            self._shamir_help.pack_forget()

    def _refresh_presets(self):
        """Tint the preset whose (n, k) matches the spinboxes; untint the rest."""
        try:
            cur = (self._n.get(), self._k.get())
        except (tk.TclError, ValueError):
            cur = None
        for key, btn in getattr(self, "_preset_btns", {}).items():
            btn.set_tint(key == cur)

    def _secret_ok(self):
        """True when the secret step is complete for the current mode."""
        if self._mode.get() == "single":
            p1 = self._pw1v.get()
            return bool(p1) and p1 == self._pw2v.get()
        try:
            n, k = self._n.get(), self._k.get()
        except (tk.TclError, ValueError):
            return False
        return 2 <= k <= n <= 20

    def _refresh_step(self):
        """Wizard highlight follows the form: Source → Protection → Secret →
        Output.  Encrypt (4) is set by _start, done by _done."""
        if self._busy or self._show_done or not hasattr(self, "_wiz"):
            return
        batch = self._src_type.get() == "batch"
        has_src = bool(self._batch_paths) if batch else bool(self._path)
        if not has_src:
            step = 0
        elif not self._secret_ok():
            step = 1
        else:
            out = (self._batch_out_var.get() if batch and hasattr(self, "_batch_out_var")
                   else self._out.get())
            step = 3 if out.strip() else 2
        self._wiz.set_step(step)

    def _clamp_k(self, *_):
        """Clamp N/K with a short debounce so that typing a two-digit
        number (e.g. "10") doesn't flash the minimum value after the first digit.
        The actual clamping is deferred by 400 ms and cancelled if another
        keystroke arrives first."""
        if hasattr(self, "_clamp_job") and self._clamp_job:
            try: self.after_cancel(self._clamp_job)
            except Exception: pass
        # Always update the summary label immediately so it tracks the current
        # raw value — but don't force-set the IntVar (which would overwrite typing).
        try:
            n, k = self._n.get(), self._k.get()
            if hasattr(self, "_shamir_summary"):
                # Show clamped values in the label without changing the spinbox
                nd = max(2, min(20, n))
                kd = max(2, min(nd, k))
                self._shamir_summary.config(
                    text=f"Any {kd} of {nd} people can unlock the file")
        except (tk.TclError, ValueError):
            pass
        self._refresh_presets()
        self._refresh_step()
        self._clamp_job = self.after(400, self._do_clamp)

    def _do_clamp(self):
        """Deferred actual clamping — runs 400 ms after the last keystroke.
        Says what it changed instead of silently rewriting the field."""
        self._clamp_job = None
        try:
            n, k = self._n.get(), self._k.get()
            note = None
            if n < 2: n = 2; self._n.set(n); note = "Minimum is 2 people"
            if n > 20: n = 20; self._n.set(n); note = "Maximum is 20 people"
            if k < 2: k = 2; self._k.set(k); note = note or "Minimum is 2 people"
            if k > 20: k = 20; self._k.set(k); note = "Maximum is 20 people"
            if k > n:
                k = n; self._k.set(k)
                note = note or f"Required to unlock can't exceed total people; set to {n}"
            if hasattr(self, "_shamir_summary"):
                self._shamir_summary.config(
                    text=f"Any {k} of {n} people can unlock the file")
            if note:
                self._flash_status(note, 3000)
        except (tk.TclError, ValueError):
            pass
        self._refresh_presets()
        self._refresh_step()

    def _on_mode(self,*_):
        self._show_done = False
        if self._mode.get()=="single":
            # Show pw panel and re-enable its fields for Tab navigation
            self._pw_panel.pack(fill="x")
            self._pw1.config(state="normal"); self._pw2.config(state="normal")
            self._sh_panel.pack_forget()
            self._secret_lbl.config(text="3  PASSWORD")
            self._mode_hint.config(text="Choose a strong password. It's the only way to unlock the file, and we never store it.")
        else:
            # Hide pw panel and disable its fields to remove them from Tab order
            self._pw_panel.pack_forget()
            self._pw1.config(state="disabled"); self._pw2.config(state="disabled")
            self._sh_panel.pack(fill="x")
            self._secret_lbl.config(text="3  SHARES")
            self._mode_hint.config(text="Give each person a unique share. The file can only be unlocked when enough people combine their shares.")
            # Re-show help panel if it was open before mode was switched away
            if self._shamir_help_visible:
                self._shamir_help.pack(fill="x", pady=(0,SP["s"]), before=self._shamir_grid)
        self._refresh_step()

    def _check_match(self, *_):
        """Live password match indicator. Suppressed until pw1 has content."""
        p1, p2 = self._pw1v.get(), self._pw2v.get()
        if not p1 or not p2:
            self._match_lbl.config(text="")
        elif p1 == p2:
            self._match_lbl.config(text=f"{ICON['ok']}  Passwords match", fg=C["success"])
        else:
            self._match_lbl.config(text=f"{ICON['err']}  Don't match", fg=C["error"])
        self._refresh_step()

    def _freeze(self):
        """Disable all interactive controls while encryption runs."""
        self._btn.enable(False)
        try: self._browse_btn.enable(False)  # Prevent browse during encrypt
        except Exception: pass
        for w in [self._pw1, self._pw2, self._out]:
            try: w.config(state="disabled")
            except Exception: pass
        # Disable FileCard so changing the file mid-encryption is blocked
        try: self._file_card.set_enabled(False)
        except Exception: pass
        # Freeze the mode / source toggles and the embed checkbox
        for ctl in (self._mode_w, self._src_toggle):
            try: ctl.set_enabled(False)
            except Exception: pass
        try: self._embed_chk.config(state="disabled")
        except Exception: pass

    def _thaw(self):
        """Re-enable all interactive controls after encryption completes or fails."""
        self._btn.enable(True)
        try: self._browse_btn.enable(True)  # Restore browse button
        except Exception: pass
        # Only re-enable pw fields in single mode — Shamir mode keeps them disabled
        if self._mode.get() == "single":
            for w in [self._pw1, self._pw2]:
                try: w.config(state="normal")
                except Exception: pass
        try: self._out.config(state="normal")
        except Exception: pass
        # Re-enable FileCard
        try: self._file_card.set_enabled(True)
        except Exception: pass
        for ctl in (self._mode_w, self._src_toggle):
            try: ctl.set_enabled(True)
            except Exception: pass
        try: self._embed_chk.config(state="normal")
        except Exception: pass
        # Only restore match label in single mode — Shamir has no password fields
        if self._mode.get() == "single":
            self._check_match()

    def _on_src_type(self, *_):
        """Show the correct picker widget for the current source type (file/folder/batch)."""
        mode = self._src_type.get()
        if mode == "batch":
            self._file_card.pack_forget()
            self._batch_frame.pack(fill="x", padx=self._P, after=self._src_toggle)
            if not self._batch_paths:
                self._build_batch_ui()
            # Clear any single-file/folder selection
            self._path = None; self._is_folder = False
        else:
            self._batch_frame.pack_forget()
            self._file_card.pack(fill="x", padx=self._P, after=self._src_toggle)
            drop = " · or drag & drop" if getattr(self, "_dnd_ok", False) else ""
            if mode == "folder":
                self._file_card.set_folder_mode(True)
                if not self._is_folder:
                    self._file_card.reset("Select a folder to encrypt",
                                          "Click anywhere" + (drop + " a folder" if drop else ""))
                    self._path = None; self._is_folder = False
            else:  # file
                self._file_card.set_folder_mode(False)
                if self._is_folder:
                    self._file_card.reset("Select a file to encrypt", "Click anywhere" + drop)
                    self._path = None; self._is_folder = False
        # Update button label and section-4 visibility to match source mode
        try:
            if mode == "batch":
                n = len(self._batch_paths)
                label = f"Encrypt {n} Files {ICON['arrow']}" if n else f"Encrypt Files {ICON['arrow']}"
                # Hide section 4 — batch has its own output folder row
                if hasattr(self, "_out_section"):
                    self._out_section.pack_forget()
            elif mode == "folder":
                label = f"Encrypt Folder {ICON['arrow']}"
                if hasattr(self, "_out_section") and not self._out_section.winfo_ismapped():
                    self._out_section.pack(fill="x", padx=0,
                                           before=self._act_rule)
            else:
                label = f"Encrypt File {ICON['arrow']}"
                if hasattr(self, "_out_section") and not self._out_section.winfo_ismapped():
                    self._out_section.pack(fill="x", padx=0,
                                           before=self._act_rule)
            self._btn.set_text(label)
        except Exception:
            pass
        self._refresh_step()

    def _build_batch_ui(self):
        """Render the batch-mode file list inside _batch_frame."""
        for w in self._batch_frame.winfo_children(): w.destroy()
        if not self._batch_paths:
            btn_row = tk.Frame(self._batch_frame, bg=C["bg"]); btn_row.pack(fill="x")
            FlatButton(btn_row, f"Select files {ICON['arrow']}", self._on_batch_select,
                       primary=False, small=False).pack(side="left")
            drop = " Or drop them here." if getattr(self, "_dnd_ok", False) else ""
            tk.Label(btn_row, text="Select multiple files to encrypt with the same settings." + drop,
                     font=F["caption"], bg=C["bg"], fg=C["text3"]).pack(side="left", padx=(SP["s"],0))
            return
        # Show file list
        hdr = tk.Frame(self._batch_frame, bg=C["bg"]); hdr.pack(fill="x", pady=(0,SP["s"]))
        tk.Label(hdr, text=f"{len(self._batch_paths)} files selected",
                 font=F["body_b"], bg=C["bg"], fg=C["text"]).pack(side="left")
        FlatButton(hdr, "Change", self._on_batch_select,
                   primary=False, small=True).pack(side="right")
        total = sum(os.path.getsize(p) for p in self._batch_paths if os.path.isfile(p))
        tk.Label(hdr, text=fmt_size(total), font=F["caption"],
                 bg=C["bg"], fg=C["text3"]).pack(side="right", padx=(0,SP["s"]))
        # File list capped at 5 visible rows
        list_frame = tk.Frame(self._batch_frame, bg=C["surface"],
                              highlightbackground=C["border"], highlightthickness=1)
        list_frame.pack(fill="x")
        visible = min(len(self._batch_paths), 5)
        for p in self._batch_paths[:visible]:
            row = tk.Frame(list_frame, bg=C["surface"]); row.pack(fill="x", padx=SP["s"], pady=SP["xs"])
            tk.Label(row, text=os.path.basename(p), font=F["caption"],
                     bg=C["surface"], fg=C["text"]).pack(side="left")
            try: sz = fmt_size(os.path.getsize(p))
            except OSError: sz = "?"
            tk.Label(row, text=sz, font=F["small"], bg=C["surface"],
                     fg=C["text3"]).pack(side="right")
        if len(self._batch_paths) > visible:
            tk.Label(list_frame,
                     text=f"  … and {len(self._batch_paths)-visible} more files",
                     font=F["small"], bg=C["surface"], fg=C["text3"],
                     anchor="w").pack(fill="x", padx=SP["s"], pady=(0,SP["xs"]))
        # Output directory row
        out_row = tk.Frame(self._batch_frame, bg=C["bg"]); out_row.pack(fill="x", pady=(SP["s"],0))
        tk.Label(out_row, text="Output folder:", font=F["caption"],
                 bg=C["bg"], fg=C["text3"]).pack(side="left")
        if not hasattr(self, "_batch_out_var"):
            self._batch_out_var = tk.StringVar()
            self._batch_out_var.trace_add("write", lambda *_: self._refresh_step())
        if not self._batch_out_var.get():
            self._batch_out_var.set(os.path.dirname(os.path.abspath(self._batch_paths[0])))
        e = styled_entry(out_row, textvariable=self._batch_out_var)
        e.pack(side="left", fill="x", expand=True, ipady=SP["s"], ipadx=SP["s"], padx=(SP["s"],0))
        e.bind("<Return>", lambda e: self._start())
        FlatButton(out_row, "Browse…", self._browse_batch_out, primary=False, small=True).pack(side="left", padx=(SP["xs"],0))
        tk.Label(self._batch_frame,
                 text="Each file will be saved as <filename>.qcx in the output folder.",
                 font=F["small"], bg=C["bg"], fg=C["text3"]).pack(anchor="w", pady=(SP["xs"],0))
        self._refresh_step()

    def _confirm_replace_batch(self):
        """Ask before discarding an existing non-trivial selection."""
        if len(self._batch_paths) <= 1:
            return True
        return confirm(self, "Replace selection?",
                       f"You have {len(self._batch_paths)} files selected. "
                       "Replace them with a new selection?",
                       yes="Replace", no="Keep")

    def _set_batch_paths(self, paths, keep_out=False):
        """Replace the batch selection.  The output folder defaults to the
        first file's folder; ``keep_out`` keeps a folder the user already
        chose (Retry N failed must not silently move the outputs)."""
        self._batch_paths = list(paths); self._show_done = False
        if hasattr(self, "_batch_out_var") and paths:
            if not (keep_out and self._batch_out_var.get().strip()):
                self._batch_out_var.set(os.path.dirname(os.path.abspath(paths[0])))
        self._set_status("")

    def _on_batch_select(self):
        if not self._confirm_replace_batch():
            return
        paths = filedialog.askopenfilenames(
            title="Select files to encrypt",
            filetypes=[("All files", "*")],
            initialdir=os.path.expanduser("~"))
        if paths:
            self._set_batch_paths(paths)
            self._build_batch_ui()
            # Update button label with file count
            try:
                self._btn.set_text(f"Encrypt {len(self._batch_paths)} Files {ICON['arrow']}")
            except Exception:
                pass

    def _browse_batch_out(self):
        d = filedialog.askdirectory(title="Output folder for encrypted files")
        if d and hasattr(self, "_batch_out_var"):
            self._batch_out_var.set(d)

    _KN_ERR = "Enter a number between 2 and 20 for both fields"

    def _kn(self):
        """(n, k) from the split fields, or None when either is not a number:
        an emptied Entry makes IntVar.get() raise, and a raise past the
        point where the form is frozen leaves the window busy with no way
        to close it (run 18 F-204)."""
        try:
            return int(self._n.get()), int(self._k.get())
        except (tk.TclError, ValueError):
            return None

    def _validate_secret(self):
        """Shared secret checks for single and batch validation."""
        if self._mode.get() == "single":
            pw = self._pw1v.get()
            if not pw: return "Password cannot be empty"
            # Match the core's floor here so the weak-password dialog cannot
            # offer "Use it anyway" on a password the core will then refuse.
            if len(pw) < cc.MIN_PASSWORD_LENGTH:
                return f"Use at least {cc.MIN_PASSWORD_LENGTH} characters"
            if pw != self._pw2v.get(): return "Passwords don't match"
            return None
        # An emptied Spinbox makes IntVar.get() raise; say so instead of
        # letting the Encrypt button turn into a silent no-op.
        try:
            n, k = self._n.get(), self._k.get()
        except (tk.TclError, ValueError):
            return EncryptorApp._KN_ERR
        if n < 2: return "Total shares must be at least 2"
        if k > n: return "Threshold can't exceed total shares"
        if k < 2: return "Threshold must be at least 2"
        if n > 20 or k > 20: return EncryptorApp._KN_ERR
        return None

    def _validate_batch(self):
        if not self._batch_paths: return "Select at least one file"
        missing = [p for p in self._batch_paths if not os.path.isfile(p)]
        if missing: return f"{len(missing)} file(s) no longer exist. Re-select"
        out_dir = getattr(self, "_batch_out_var", None) and self._batch_out_var.get().strip()
        if not out_dir: return "Specify an output folder"
        if not os.path.isdir(out_dir): return f"Output folder does not exist: {out_dir}"
        if not os.access(out_dir, os.W_OK): return f"Output folder is not writable: {out_dir}"
        return EncryptorApp._validate_secret(self)

    def _on_folder(self, path):
        """Called when a directory is selected (parallel to _on_file).
        The tree walk runs off the main thread so a large folder doesn't
        freeze the window; the card shows "Scanning…" until it returns."""
        self._path = path; self._is_folder = True; self._show_done = False
        if self._out_auto or not self._out.get().strip():
            base = os.path.join(os.path.dirname(os.path.abspath(path)),
                                os.path.basename(path))
            self._out.delete(0,"end"); self._out.insert(0, base + ".qcx")
            self._out_auto = True
        self._file_card.load_folder(path, 0, 0, scanning=True)
        def _scan():
            try:
                count, total = _folder_stats(path)
            except Exception:
                count, total = 0, 0
            def _apply():
                # Ignore a stale scan if the user has already picked elsewhere
                if self._path == path and self._is_folder:
                    self._file_card.load_folder(path, count, total)
            safe_after(self, _apply)
        threading.Thread(target=_scan, daemon=True).start()
        self._set_status(""); self._refresh_step()
        self._on_embed_toggle()
        self.title(f"{os.path.basename(path)}/ — QuantaCrypt · Encrypt")
        self.after(80, lambda: self._cv.yview_moveto(0.55))

    def _on_file(self,path):
        self._path=path; self._is_folder=False; self._show_done=False
        # Refresh output path when auto-generated or empty; preserve manual edits
        if self._out_auto or not self._out.get().strip():
            base = os.path.splitext(path)[0]  # Strip source extension
            self._out.delete(0,"end"); self._out.insert(0, base + ".qcx")
            self._out_auto = True  # still auto-generated
            self._out_hint.config(text="Auto-generated. Click Browse… to choose a different location")
        self._set_status(""); self._refresh_step()
        self._on_embed_toggle()
        self.title(f"{os.path.basename(path)} — QuantaCrypt · Encrypt")
        self.after(80, lambda: self._cv.yview_moveto(0.55))  # Nudge to reveal lower form

    def _browse_out(self):
        # Pre-seed directory from current output field
        cur=self._out.get().strip()
        init_dir=os.path.dirname(os.path.abspath(cur)) if cur else ""
        p=filedialog.asksaveasfilename(initialdir=init_dir,defaultextension=".qcx",
            filetypes=[("QuantaCrypt","*.qcx"),("All files","*")])
        if p:
            self._out.delete(0,"end"); self._out.insert(0,p)
            self._out_auto = False  # Browsed path is user-supplied
            self._out_hint.config(text=".qcx is QuantaCrypt's encrypted format, safe to store or share")
            self._refresh_step()

    def _validate(self):
        if self._src_type.get() == "batch": return self._validate_batch()
        if not self._path: return "Select a file or folder first"
        if self._is_folder:
            if not os.path.isdir(self._path): return "Folder no longer exists. Please re-select"
        else:
            if not os.path.isfile(self._path): return "Select a file first"
        out=self._out.get().strip()
        if not out: return "Specify an output path"
        try:
            if not self._is_folder and os.path.exists(out) and os.path.samefile(self._path,out):
                return "Output path is the same as the input. Choose a different location"
        except OSError: pass
        if self._is_folder:
            # The folder is streamed straight into the cipher, but the output
            # file itself grows in the output directory while the walk runs;
            # placing it inside the source tree would archive the growing
            # output into itself.
            src_abs = os.path.abspath(self._path)
            out_abs = os.path.abspath(out)
            if out_abs == src_abs or out_abs.startswith(src_abs + os.sep):
                return "Output must be outside the folder being encrypted"
        # Validate output directory exists and is writable
        out_dir = os.path.dirname(os.path.abspath(out)) or "."
        if not os.path.isdir(out_dir):
            return f"Output directory does not exist: {out_dir}"
        if not os.access(out_dir, os.W_OK):
            return f"Output directory is not writable: {out_dir}"
        return EncryptorApp._validate_secret(self)

    def _confirm_weak_password(self) -> bool:
        """Warn if the password is rated Weak (zxcvbn score 0 or 1).

        The strength bar already scored this text on a worker thread — reuse
        it rather than running zxcvbn again on the main thread. Returns False
        if the user chose to pick another password.

        Shared by the single-file and batch paths: this used to live after
        _start()'s batch early-return, so encrypting forty files at once was
        the highest-blast-radius operation in the app and the only one with
        no warning at all.
        """
        if self._mode.get() != "single":
            return True
        if self._strength.score_for(self._pw1v.get()) >= 2:
            return True
        return confirm(self, "Weak password",
                       "Your password is rated Weak and could be guessed relatively "
                       "easily. A longer password mixing words, numbers and symbols "
                       "is safer.\n\nContinue with this password anyway?",
                       yes="Use it anyway", no="Choose another", danger=True)

    def _start(self):
        if self._busy: return
        # Starting a new encryption clears the results area — including any
        # unsaved Shamir share cards from the previous run.  Same guard as
        # _reset()/_close(); consenting (or having saved) disarms it.
        if not self._check_shares_saved(): return
        self._shares_pending = set()
        self._show_done = False
        # Batch mode: encrypt each file individually with the same settings
        if self._src_type.get() == "batch":
            self._start_batch(); return
        err=self._validate()
        if err:
            self._set_error(err)
            self.after(50, lambda: self._cv.yview_moveto(1.0))  # Scroll after layout reflow
            return
        out=self._out.get().strip()
        if not self._confirm_weak_password():
            return
        # K=N means every shareholder must participate — unusual and worth confirming.
        if self._mode.get() == "shamir":
            k, n = self._k.get(), self._n.get()
            if k == n:
                if not confirm(self, "All people required",
                               f"\"Required to unlock\" and \"total people\" are both {n}, so every "
                               "single person must participate. If even one share is lost, the "
                               "file can never be unlocked. For a safety margin, set \"required "
                               f"to unlock\" lower.\n\nContinue with {k}-of-{n}?",
                               yes=f"Continue with {k}-of-{n}", no="Go back", danger=True):
                    return
        if os.path.exists(out):
            if not confirm(self, "Overwrite?",
                           f"{os.path.basename(out)} already exists. Overwrite it?",
                           yes="Overwrite", no="Cancel", danger=True):
                return
        # Everything Tk-side is read before the form freezes: nothing after
        # this line may raise (see _kn).
        n, k = self._kn() or (0, 0)
        self._set_status(""); self._busy=True
        self._cancel_event.clear()
        self._new_prog(self._stages_for(is_folder=self._is_folder, mode=self._mode.get()))
        self._cancel_row.pack(fill="x", padx=self._P, pady=(0, SP["s"]), before=self._results)
        self._cancel_btn.enable(True)
        self._prog.start(); self._freeze(); self._wiz.set_step(4)
        self.after(50, lambda: self._cv.yview_moveto(1.0))
        for w in self._results.winfo_children(): w.destroy()
        # Capture all Tk widget state on the main thread before spawning worker
        # Freeze k/n for every later share-artifact path (see __init__).
        self._result_k = k
        self._result_n = n
        params = {
            "path":      self._path,
            "out":       out,
            "mode":      self._mode.get(),
            "pw":        self._pw1v.get(),
            "n":         n,
            "k":         k,
            "embed":     self._embed_dec.get(),
            "is_folder": self._is_folder,
        }
        threading.Thread(target=self._run, args=(params,), daemon=True).start()
        # Cancel is the only live control now; give it the keyboard.
        self._cancel_btn.focus_set()

    # ── Per-run progress bar ──────────────────────────────────────────────
    @staticmethod
    def _stages_for(*, is_folder, mode):
        """[(semantic_idx, name, weight)] for THIS run: no "Compressing
        folder" for plain files, no "Securing password" in split mode."""
        sel = []
        for sem, (name, w) in enumerate(STAGES):
            if sem == STAGE_COMPRESS and not is_folder: continue
            if sem == STAGE_ARGON and mode != "single": continue
            sel.append((sem, name, w))
        return sel

    def _new_prog(self, stages):
        """Replace the progress bar with one whose dots match ``stages``
        and pack it into the progress slot above the results."""
        old = getattr(self, "_prog", None)
        if old is not None:
            try: old.stop(); old.destroy()
            except Exception: pass
        self._run_stages = stages
        self._stage_map = {sem: i for i, (sem, _, _) in enumerate(stages)}
        self._prog = StagedProgressBar(self._body, [(n, w) for _, n, w in stages])
        self._prog.pack(fill="x", padx=self._P, pady=(0, SP["xs"]), before=self._results)
        return self._prog

    def _advance(self, sem, msg=None):
        """Main-thread: move the bar to semantic stage ``sem`` with the
        friendly label (+ NN% if the core reported one)."""
        idx = self._stage_map.get(sem)
        if idx is None or not self._busy:
            return
        self._prog.advance(idx, _stage_label(sem, msg))

    def _prog_cb(self,msg):
        sem = _find_stage(msg)
        if sem is not None:
            safe_after(self, lambda: self._advance(sem, msg))

    def _start_batch(self):
        """Encrypt all selected files in sequence with the same settings.
        Each file becomes its own .qcx in the output folder."""
        err = self._validate_batch()
        if err:
            self._set_error(err)
            self.after(50, lambda: self._cv.yview_moveto(1.0))
            return
        if not self._confirm_weak_password():
            return
        out_dir = self._batch_out_var.get().strip()
        # Unique per-input output names (collision-suffixed), then warn
        # about overwriting anything that already exists on disk.
        batch_outs = _batch_output_paths(self._batch_paths, out_dir)
        would_overwrite = []
        for dest in batch_outs:
            if os.path.exists(dest):
                would_overwrite.append(os.path.basename(dest))
        if would_overwrite:
            names = ", ".join(would_overwrite[:3])
            if len(would_overwrite) > 3: names += f" … (+{len(would_overwrite)-3} more)"
            if not confirm(self, "Overwrite?",
                           f"These files already exist and will be overwritten:\n{names}",
                           yes="Overwrite", no="Cancel", danger=True):
                return
        n, k = self._kn() or (0, 0)            # before the freeze — see _kn
        self._set_status(""); self._busy = True
        self._cancel_event.clear()
        # One bar for the whole batch; per-file stages feed the inner
        # fraction so it climbs 0→100% once instead of sawing per file.
        self._new_prog([(STAGE_PAYLOAD, "Encrypting files", 1.0)])
        self._batch_inner = self._stages_for(is_folder=False, mode=self._mode.get())
        self._cancel_row.pack(fill="x", padx=self._P, pady=(0, SP["s"]), before=self._results)
        self._cancel_btn.enable(True)
        self._prog.start(); self._freeze(); self._wiz.set_step(4)
        self.after(50, lambda: self._cv.yview_moveto(1.0))
        for w in self._results.winfo_children(): w.destroy()
        self._result_k = k
        self._result_n = n
        batch_params = {
            "paths":   list(self._batch_paths),
            "outs":    batch_outs,
            "out_dir": out_dir,
            "mode":    self._mode.get(),
            "pw":      self._pw1v.get(),
            "n":       n,
            "k":       k,
            "embed":   self._embed_dec.get(),
        }
        threading.Thread(target=self._run_batch, args=(batch_params,), daemon=True).start()
        self._cancel_btn.focus_set()

    def _advance_batch(self, i, total, sem, inner):
        """Main-thread: overall = (files done + fraction of this one) / total."""
        if not self._busy:
            return
        pct = int((i - 1 + inner) / max(total, 1) * 100)
        self._prog.advance(0, f"File {i} of {total} — {STAGES[sem][0]}  {pct}%")

    def _batch_prog_cb(self, i, total):
        """progress_cb for file ``i`` of the batch."""
        stages = self._batch_inner
        smap = {sem: n for n, (sem, _, _) in enumerate(stages)}
        tot_w = sum(w for _, _, w in stages) or 1.0
        def _cb(msg):
            sem = _find_stage(msg)
            if sem is None or sem not in smap:
                return
            idx = smap[sem]
            start = sum(w for _, _, w in stages[:idx]) / tot_w
            end = start + stages[idx][2] / tot_w
            m = re.search(r"(\d+)%", msg or "")
            sub = min(int(m.group(1)), 100) / 100.0 if m else 0.0
            inner = start + sub * (end - start)
            safe_after(self, lambda: self._advance_batch(i, total, sem, inner))
        return _cb

    def _run_batch(self, bp):
        """Worker: encrypt each file in bp["paths"] one by one through
        core.package.encrypt_to_qcx.  Stops at the next chunk boundary
        after Cancel; files already written stay."""
        succeeded, failed = [], []
        total = len(bp["paths"])
        cancelled = False
        _cancel_check = self._cancel_event.is_set
        dec = self._find_dec() if bp["embed"] else None
        for i, (path, out) in enumerate(zip(bp["paths"], bp["outs"]), 1):
            if _cancel_check():
                cancelled = True
                break
            cb = self._batch_prog_cb(i, total)
            first = self._batch_inner[0][0]
            safe_after(self, lambda i=i, first=first: self._advance_batch(i, total, first, 0.0))
            try:
                res = pkg.encrypt_to_qcx(
                    path, out, mode=bp["mode"], password=bp["pw"],
                    k=bp["k"], n=bp["n"], progress=cb,
                    cancel_check=_cancel_check, embed_binary=dec)
                succeeded.append((out, [sh["code"] for sh in res["shares"]],
                                  [sh["mnemonic"] for sh in res["shares"]]))
            except cc.CancelledOperation:
                cancelled = True
                break
            except Exception as ex:
                failed.append((path, ex))
        bp["pw"] = None
        safe_after(self, lambda: self._done_batch(succeeded, failed, bp, cancelled))

    def _retry_failed(self, paths):
        """Re-run the batch with only the files that failed, into the SAME
        output folder.  The unsaved-shares guard runs before anything is
        replaced so a "Go back" leaves the summary (and its share cards)
        exactly as it was."""
        if not self._check_shares_saved():
            return
        self._shares_pending = set()
        self._set_batch_paths(paths, keep_out=True)
        self._build_batch_ui()
        self._start()

    def _done_batch(self, succeeded, failed, bp, cancelled=False):
        """Show batch completion summary."""
        self._busy = False
        self._cancel_row.pack_forget()
        if cancelled:
            self._prog.stop(); self._prog.pack_forget()
        else:
            self._prog.complete()
        self._thaw()
        self._wiz.set_step(4 if cancelled else len(self.STEPS))
        self._show_done = not cancelled
        self._pw1v.set(""); self._pw2v.set("")
        n_ok, n_fail = len(succeeded), len(failed)
        total = len(bp["paths"])
        if cancelled:
            skipped = total - n_ok - n_fail
            self._set_status(f"Cancelled. {n_ok} of {total} files were encrypted; "
                             f"{skipped} not started, no partial file was written.")
        else:
            self._set_status("")
        if failed:
            notify("Batch encryption finished",
                   f"{n_ok} succeeded, {n_fail} failed")
        elif not cancelled:
            notify("Batch encryption complete",
                   f"{n_ok} file{'s' if n_ok!=1 else ''} encrypted")
        colour = C["success"] if not (failed or cancelled) else C["warning"]
        ok = tk.Frame(self._results, bg=C["surface"],
                      highlightbackground=colour, highlightthickness=1)
        ok.pack(fill="x", pady=(SP["l"],0))
        ok_in = tk.Frame(ok, bg=C["surface"]); ok_in.pack(fill="x", padx=SP["l"], pady=SP["m"])
        summary = f"{ICON['ok']}  {n_ok} file{'s' if n_ok!=1 else ''} encrypted"
        if n_fail:
            summary += f"  ·  {n_fail} failed"
        if cancelled:
            summary += "  ·  cancelled"
        tk.Label(ok_in, text=summary, font=F["body_b"], bg=C["surface"],
                 fg=colour).pack(side="left")
        # Folder path on its own row under the summary (not beside it)
        tk.Label(ok, text=bp["out_dir"], font=F["caption"],
                 bg=C["surface"], fg=C["text3"], wraplength=380,
                 anchor="w", justify="left").pack(fill="x", padx=SP["l"], pady=(0,SP["xs"]))
        for out_path, shares, _mn in succeeded[:5]:
            row = tk.Frame(ok, bg=C["surface"]); row.pack(fill="x", padx=SP["l"], pady=(0,SP["xs"]))
            tk.Label(row, text=f"  {ICON['ok']}  {os.path.basename(out_path)}", font=F["caption"],
                     bg=C["surface"], fg=C["success"]).pack(side="left")
            try: sz = fmt_size(os.path.getsize(out_path))
            except OSError: sz = ""
            if sz: tk.Label(row, text=sz, font=F["small"], bg=C["surface"],
                            fg=C["text3"]).pack(side="right")
        if len(succeeded) > 5:
            tk.Label(ok, text=f"  … and {len(succeeded)-5} more",
                     font=F["small"], bg=C["surface"], fg=C["text3"],
                     anchor="w").pack(fill="x", padx=SP["l"], pady=(0,SP["xs"]))
        for path, exc in failed:
            tk.Label(ok, text=f"  {ICON['err']}  {os.path.basename(path)}: {friendly_error(exc)}",
                     font=F["caption"], bg=C["surface"], fg=C["error"], anchor="w",
                     justify="left", wraplength=490).pack(fill="x", padx=SP["l"], pady=(0,SP["xs"]))
        # Shamir shares: render a share section per file that had shares generated
        files_with_shares = [(out_path, shares, mn) for out_path, shares, mn in succeeded if shares]
        if files_with_shares:
            warn = tk.Frame(self._results, bg=C["surface"],
                            highlightbackground=C["warning"], highlightthickness=1)
            warn.pack(fill="x", pady=(SP["s"],0))
            w_hdr = tk.Frame(warn, bg=C["surface"]); w_hdr.pack(fill="x", padx=SP["l"], pady=(SP["s"],SP["xs"]))
            k = self._result_k or self._k.get()
            tk.Label(w_hdr,
                     text=f"Save key shares: {len(files_with_shares)} file{'s' if len(files_with_shares)!=1 else ''} need share distribution",
                     font=F["body_b"], bg=C["surface"], fg=C["warning"]).pack(anchor="w")
            tk.Label(warn,
                     text="Each file has its own set of shares. Save individual share files "
                          "for each encrypted file before closing.",
                     font=F["caption"], bg=C["surface"], fg=C["text3"],
                     wraplength=490, anchor="w").pack(fill="x", padx=SP["l"], pady=(0,SP["s"]))
            for out_path, shares, known_mn in files_with_shares:
                # Per-file collapsible section
                sec = tk.Frame(self._results, bg=C["surface"],
                               highlightbackground=C["border"], highlightthickness=1)
                sec.pack(fill="x", pady=(0,SP["s"]))
                sec_hdr = tk.Frame(sec, bg=C["surface"]); sec_hdr.pack(fill="x", padx=SP["l"], pady=(SP["s"],SP["xs"]))
                tk.Label(sec_hdr, text=os.path.basename(out_path),
                         font=F["body_b"], bg=C["surface"], fg=C["text"]).pack(side="left")
                FlatButton(sec_hdr, f"Save individual files {ICON['arrow']}",
                           lambda _p=out_path, _s=shares, _sec=sec: self._save_individual_shares(
                               _s, os.path.splitext(os.path.basename(_p))[0], qcx_path=_p, banner_frame=_sec),
                           primary=True, small=False).pack(side="right")
                # Share cards (collapsed — just the save button is enough for batch)
                mnemonics = _mnemonics_for(shares, k, known_mn)
                for i, sh in enumerate(shares, 1):
                    mn = mnemonics[i-1] if i-1 < len(mnemonics) else None
                    ShareCard(sec, i, sh, mnemonic=mn).pack(fill="x", padx=SP["s"], pady=(0,SP["s"]))
            self._shares_pending = {op for op, _sh, _mn in files_with_shares}
        btn_row = tk.Frame(ok, bg=C["surface"]); btn_row.pack(fill="x", padx=SP["l"], pady=(SP["s"],SP["m"]))
        first = None
        if failed:
            first = FlatButton(btn_row, f"Retry {n_fail} failed {ICON['arrow']}",
                               lambda: self._retry_failed([p for p, _ in failed]),
                               primary=True, small=True)
            first.pack(side="left", padx=(0,SP["s"]))
        again = FlatButton(btn_row, f"Encrypt another batch {ICON['arrow']}",
                           lambda: self._reset(keep_batch=True),
                           primary=False, small=True)
        again.pack(side="left")
        if succeeded:
            FlatButton(btn_row, REVEAL_LABEL,
                       lambda: self._reveal_ui(succeeded[0][0]),
                       primary=False, small=True).pack(side="left", padx=(SP["s"],0))
        self.after(50, lambda: self._cv.yview_moveto(1.0))
        _fb = first or again
        self.after(50, lambda: _fb.focus_set() if _fb.winfo_exists() else None)

    def _reveal_ui(self, path, open_file=False):
        """_reveal + a status line when the OS handler couldn't be launched."""
        if not _reveal(path, open_file=open_file):
            what = "open the file" if open_file else "open the file manager"
            self._set_status(f"Couldn't {what}. The file is at {path}")

    def _run(self, p):
        """Worker thread.  core.package.encrypt_to_qcx does the work —
        streaming a folder straight into the cipher (no plaintext staging
        file), the optional embedded decryptor, streaming AES-GCM, the MAGIC
        tail and the atomic rename — so the Tk wizard and qc-core write
        byte-identical files."""
        out = p["out"]
        try:
            dec = self._find_dec() if p["embed"] else None
            if p["is_folder"]:
                safe_after(self, lambda: self._advance(STAGE_COMPRESS, None))
            res = pkg.encrypt_to_qcx(
                p["path"], out, mode=p["mode"], password=p["pw"],
                k=p["k"], n=p["n"], progress=self._prog_cb,
                cancel_check=self._cancel_event.is_set, embed_binary=dec)
            shares = [sh["code"] for sh in res["shares"]]
            mnemonics = [sh["mnemonic"] for sh in res["shares"]]
            try:
                dec_size = os.path.getsize(dec) if dec else 0
            except OSError:
                dec_size = 0
            safe_after(self, lambda: self._done(out, shares, bool(dec), dec_size,
                                                mnemonics=mnemonics))
        except cc.CancelledOperation:
            safe_after(self, self._cancelled)
        except Exception as ex:
            safe_after(self, lambda exc=ex: self._fail(exc))
        finally:
            # Clear password from worker params to reduce memory exposure
            p["pw"] = None

    def _find_dec(self):
        # Frozen builds are onedir: sys.executable depends on the adjacent
        # _internal tree, so embedding it produces a .qcx that can't run
        # standalone — and appending payload bytes invalidates the arm64
        # code signature ("killed: 9").  No embed until a dedicated onefile
        # decryptor artifact exists.
        if getattr(sys,"frozen",False): return None
        d=os.path.dirname(os.path.abspath(__file__))
        for name in [".quantacrypt-decryptor","quantacrypt-decryptor","quantacrypt"]:
            for base in [d,os.path.join(d,"dist")]:
                p=os.path.join(base,name)
                if os.path.isfile(p): return p
        return None

    def _done(self,out,shares,embedded=True,dec_size=0,mnemonics=None):
        self._busy=False; self._prog.complete(); self._cancel_row.pack_forget(); self._thaw()
        # set_step past the last step index → all circles show ✓ (complete state)
        self._wiz.set_step(len(self.STEPS)); self._show_done = True
        self._set_status("")                     # Clear any stale busy/error message
        self._pw1v.set(""); self._pw2v.set("")  # Clear passwords after success
        self._match_lbl.config(text="")          # clear "✓ Passwords match" residue
        notify("Encryption complete", os.path.basename(out))

        ok=tk.Frame(self._results,bg=C["surface"],highlightbackground=C["success"],highlightthickness=1)
        ok.pack(fill="x",pady=(SP["l"],SP["m"] if shares else 0))
        ok_in=tk.Frame(ok,bg=C["surface"]); ok_in.pack(fill="x",padx=SP["l"],pady=SP["m"])
        try:
            out_size = os.path.getsize(out)
        except OSError:
            out_size = 0
        if embedded:
            # Use dec_size passed from _run (computed at write time)
            payload_size = out_size - dec_size
            size_label = (f"{fmt_size(out_size)}  ({fmt_size(dec_size)} decryptor + "
                          f"{fmt_size(max(0, payload_size))} data)")
        else:
            size_label = fmt_size(out_size)
        tk.Label(ok_in,text=f"{ICON['ok']}  Encrypted successfully",font=F["body_b"],bg=C["surface"],fg=C["success"]).pack(side="left")
        tk.Label(ok_in,text=size_label,font=F["caption"],bg=C["surface"],fg=C["text3"]).pack(side="right")
        tk.Label(ok,text=os.path.basename(out),font=F["mono"],bg=C["surface"],fg=C["text2"]).pack(anchor="w",padx=SP["l"],pady=(0,SP["xs"]))
        # Confirm which source was encrypted
        if self._path:
            src_label = (os.path.basename(self._path) + "/"
                         if self._is_folder else os.path.basename(self._path))
            tk.Label(ok,text=f"from  {src_label}",font=F["caption"],
                     bg=C["surface"],fg=C["text3"]).pack(anchor="w",padx=SP["l"],pady=(0,SP["xs"]))
        if embedded:
            embed_lines = [
                "Includes the decryptor, so recipients can run this file directly on the same OS,",
                "or open it via quantacrypt on any platform.",
                # Recipients need execute permission
                f"Recipients may need to run  chmod +x {os.path.basename(out)}  before executing.",
                # OS security warnings
                f"If macOS blocks it, right-click {ICON['arrow']} Open to bypass the security warning.",
            ]
            tk.Label(ok, text="\n".join(embed_lines),
                font=F["caption"], bg=C["surface"], fg=C["text3"],
                justify="left").pack(anchor="w", padx=SP["l"], pady=(0,SP["s"]))
        else:
            # Informational note, not a warning — use text3 (gray) not warning (yellow)
            tk.Label(ok,text="Recipients will need the quantacrypt app to open this file.",
                font=F["caption"],bg=C["surface"],fg=C["text3"],justify="left").pack(anchor="w",padx=SP["l"],pady=(0,SP["s"]))
        btn_row=tk.Frame(ok,bg=C["surface"]); btn_row.pack(fill="x",padx=SP["l"],pady=(0,SP["m"]))
        again_btn=FlatButton(btn_row,f"Encrypt another {ICON['arrow']}",self._reset,primary=False,small=True)
        again_btn.pack(side="left")
        FlatButton(btn_row,REVEAL_LABEL,lambda:self._reveal_ui(out),primary=False,small=True).pack(side="left",padx=(SP["s"],0))
        # Open the output file directly (mirrors open-file on decrypt success)
        FlatButton(btn_row,"Open file",lambda:self._reveal_ui(out,open_file=True),primary=False,small=True).pack(side="left",padx=(SP["s"],0))
        if not shares:
            self.after(50, lambda: self._cv.yview_moveto(1.0))
            self.after(50, lambda: again_btn.focus_set() if again_btn.winfo_exists() else None)
            return
        # Guard: warn if the user navigates away.  Keyed by the output this
        # run wrote — picking another file afterwards changes _path/_out
        # while these cards stay live, and share files were being named and
        # fingerprinted from the *new* form (holding the old shares).
        self._shares_pending = {out}
        self._pending_shares = shares  # keep ref for save dialog
        orig_name = os.path.basename(self._path or "")
        k = self._result_k or self._k.get()
        n = self._result_n or self._n.get()
        self._shares_warn=tk.Frame(self._results,bg=C["surface"],highlightbackground=C["warning"],highlightthickness=1)
        warn = self._shares_warn
        warn.pack(fill="x",pady=(0,SP["s"]))
        # Summary text on its own row
        tk.Label(warn, text=f"Send each person their share. Any {k} of {n} can unlock the file.",
                 font=F["body_b"], bg=C["surface"], fg=C["warning"],
                 anchor="w").pack(fill="x", padx=SP["l"], pady=(SP["s"],SP["s"]))
        # Buttons on a separate row so they don't overlap the text
        btn_grp = tk.Frame(warn, bg=C["surface"]); btn_grp.pack(fill="x", padx=SP["l"], pady=(0,SP["s"]))
        # Primary: save one file per person (new feature)
        save_btn = FlatButton(btn_grp, f"Save individual files {ICON['arrow']}",
                   lambda: self._save_individual_shares(shares, orig_name, qcx_path=out,
                                                        banner_frame=self._shares_warn),
                   primary=True, small=False)
        save_btn.pack(side="left")
        # Secondary: save all shares in one combined file (original behaviour)
        FlatButton(btn_grp, "Save combined file",
                   lambda: self._save_shares(shares, orig_name, qcx_path=out),
                   primary=False, small=False).pack(side="left", padx=(SP["s"],0))
        # Copy all shares to clipboard in one click
        self._copy_all_btn = FlatButton(btn_grp, "Copy all",
                   lambda: self._copy_all_shares(shares), primary=False, small=True)
        self._copy_all_btn.pack(side="left", padx=(SP["s"],0))
        # One sentence on what the three buttons mean for safety
        tk.Label(warn, text="Saving to files is what protects you; the clipboard clears in 60 s.",
                 font=F["caption"], bg=C["surface"], fg=C["text3"], wraplength=500,
                 anchor="w", justify="left").pack(fill="x", padx=SP["l"], pady=(0,SP["xs"]))
        # Clipboard countdown on its own row
        timer_row = tk.Frame(warn, bg=C["surface"]); timer_row.pack(fill="x", padx=SP["l"], pady=(0,SP["s"]))
        self._copy_all_clip_lbl = tk.Label(timer_row, text="", font=F["small"],
                                            bg=C["surface"], fg=C["text3"])
        self._copy_all_clip_lbl.pack(side="left")
        # Root-owned (see ShareCard): the clear must survive this window closing.
        self._copy_all_timer = ClipboardTimer(_root_of(self), self._copy_all_clip_lbl)
        self.after(50, lambda: save_btn.focus_set() if save_btn.winfo_exists() else None)
        mnemonics = _mnemonics_for(shares, k, mnemonics)
        for i,sh in enumerate(shares,1):
            mn=mnemonics[i-1] if i-1<len(mnemonics) else None
            ShareCard(self._results,i,sh,mnemonic=mn).pack(fill="x",pady=(0,SP["s"]))
        # Next-steps checklist — guides non-technical users through what to do now
        steps = tk.Frame(self._results, bg=C["surface"],
                         highlightbackground=C["accent"], highlightthickness=1)
        steps.pack(fill="x", pady=(SP["xs"], SP["s"]))
        tk.Label(steps, text="What to do next", font=F["body_b"],
                 bg=C["surface"], fg=C["accent_text"]).pack(anchor="w", padx=SP["l"], pady=(SP["s"], SP["s"]))
        can_test = bool(self._on_close)   # decryptor hand-off needs the launcher to return to
        checklist = [
            "1.  Save the shares (one file per person, or one combined file)",
            "2.  Keep the encrypted .qcx file; it's safe to store anywhere",
            (f"3.  Test unlocking it with {k} shares before you hand them out"
             if can_test else
             f"3.  Test unlocking from the Home screen: Decrypt {ICON['arrow']} pick this file "
             f"{ICON['arrow']} enter {k} shares"),
            "4.  Then give each person only their own share, never the others",
        ]
        for line in checklist:
            tk.Label(steps, text=line, font=F["caption"],
                     bg=C["surface"], fg=C["text2"], anchor="w",
                     wraplength=480, justify="left").pack(fill="x", padx=SP["l"], pady=(0,SP["xs"]))
        if can_test:
            FlatButton(steps, f"Test decryption {ICON['arrow']}",
                       lambda: self._test_decrypt(out),
                       primary=False, small=True).pack(anchor="w", padx=SP["l"], pady=(SP["xs"], SP["s"]))
        else:
            tk.Label(steps, text="", font=F["small"], bg=C["surface"]).pack(pady=(0, SP["s"]))
        # Force geometry to settle, then schedule cancellable scroll
        self._body.update_idletasks()
        if self._scroll_job is not None:
            try: self.after_cancel(self._scroll_job)
            except Exception: pass
        self._scroll_job = self.after(150, lambda: self._cv.yview_moveto(1.0))

    def _test_decrypt(self, out):
        """Hand the just-written .qcx to the decryptor (M18).  The launcher's
        on_close moves to the decryptor so Home reappears when it closes."""
        if not self._check_shares_saved():
            return
        try:
            from quantacrypt.ui.decryptor import DecryptorApp, load_pkg
            pkg = load_pkg(out)
            cx = self.winfo_x() + self.winfo_width() // 2
            cy = self.winfo_y() + self.winfo_height() // 2
            DecryptorApp(self.master, payload=pkg, qcx_path=out,
                         on_close=self._on_close, center_at=(cx, cy))
        except Exception as exc:
            self._set_error(f"Couldn't open the decryptor: {friendly_error(exc)}")
            return
        self._shares_pending = set()
        self.destroy()

    def _copy_all_shares(self, shares):
        """Copy all share strings to the clipboard as one share per line."""
        try:
            text = "\n".join(shares)
            # A full threshold's worth of key material in one action — the
            # concealed marker matters most here.
            if hasattr(self, "_copy_all_timer"):
                self._copy_all_timer.copy(self, text)
            else:
                copy_secret(self, text)
            self._copy_all_btn.set_text(f"{ICON['ok']} Copied")
            self.after(1500, lambda: self._copy_all_btn.set_text("Copy all")
                       if self._copy_all_btn.winfo_exists() else None)
        except Exception:
            self._copy_all_btn.set_text(f"{ICON['warn']} Failed")
            self.after(2000, lambda: self._copy_all_btn.set_text("Copy all")
                       if self._copy_all_btn.winfo_exists() else None)

    def _reset(self, keep_batch=False):
        """Back to an empty form.  ``keep_batch`` keeps batch mode and the
        output folder so "Encrypt another batch" doesn't drop the user
        back into single-file mode."""
        if not self._check_shares_saved(): return
        # Cancel any pending scroll-to-bottom from _done
        if self._scroll_job is not None:
            try: self.after_cancel(self._scroll_job)
            except Exception: pass
            self._scroll_job = None
        # Remember last-used mode and Shamir config across "Encrypt another";
        # read before anything is cleared, guarded (see _kn).
        last_mode = self._mode.get()
        last_kn = self._kn()
        self._shares_pending=set(); self._pending_shares=[]; self._show_done=False
        self._path=None; self._is_folder=False; self._batch_paths=[]
        self._out.delete(0,"end")
        self._out_auto=False
        self._pw1v.set(""); self._pw2v.set("")
        self._pw1.config(show="•"); self._pw2.config(show="•")
        self._eye1_btn.set_text("Show"); self._eye2_btn.set_text("Show")
        self._mode.set(last_mode); self._embed_dec.set(False); self._set_status("")
        if last_kn is not None:
            self._n.set(last_kn[0]); self._k.set(last_kn[1])
        for w in self._results.winfo_children(): w.destroy()
        self._prog.pack_forget()
        if keep_batch:
            self._src_type.set("batch")
            self._build_batch_ui()
            self._on_src_type()
        else:
            self._src_type.set("file")   # restore toggle to File mode
            self._file_card.pack(fill="x", padx=self._P, after=self._src_toggle)   # ensure visible after batch mode
            self._batch_frame.pack_forget()
            if hasattr(self, "_batch_out_var"): self._batch_out_var.set("")
            self._file_card.reset("Select a file to encrypt")  # sub text from set_drop_supported
        self._wiz.set_step(0)
        self._on_embed_toggle()
        self.title("QuantaCrypt · Encrypt")
        self.after(10, lambda: self._cv.yview_moveto(0))  # Scroll back to top
        # Restore focus so keyboard users have a clear starting point
        if keep_batch:
            self.after(20, self._src_toggle.focus_set)
        else:
            self.after(20, self._file_card.focus_set)

    def _request_cancel(self):
        """Set the cancel flag; the worker's next chunk-boundary check
        raises CancelledOperation and cleans up the partial output."""
        if not self._busy:
            return
        self._cancel_event.set()
        try:
            self._cancel_btn.enable(False)
        except Exception:
            pass
        self._set_status("Cancelling. Finishing the current chunk…")

    def _cancelled(self):
        """Post-cancel UI reset."""
        self._busy = False
        self._prog.stop()
        self._prog.pack_forget()
        self._cancel_row.pack_forget()
        self._thaw()
        self._wiz.set_step(4)
        self._set_status("Encryption cancelled. No output was written.")
        self.after(20, self._btn.focus_set)

    def _fail(self, exc):
        """Worker failure.  ``exc`` is the exception (or a str fallback);
        the shared friendly_error vocabulary does the mapping, with two
        encryption-specific overrides."""
        self._busy=False; self._prog.stop(); self._prog.pack_forget(); self._cancel_row.pack_forget(); self._thaw(); self._wiz.set_step(4)
        raw = str(exc)
        if isinstance(exc, MemoryError) or "too large" in raw.lower():
            msg = "File is too large to process. Try a smaller file or free up memory."
        elif isinstance(exc, BaseException):
            msg = friendly_error(exc)
            if msg == raw or not msg:
                msg = f"Something went wrong during encryption: {raw or type(exc).__name__}. " \
                      "Try a different output location or restart the app."
        else:
            msg = raw or "Something went wrong during encryption. Try a different output location or restart the app."
        self._set_error(msg)
        # Scroll to bottom so the error label is visible
        self.after(50, lambda: self._cv.yview_moveto(1.0))  # Reflow delay
        self.after(20, self._btn.focus_set)

    def _save_individual_shares(self, shares, orig, qcx_path=None, banner_frame=None):
        """Save each share as its own file in a chosen folder.
        Files are named  <stem>.share-1-of-N.txt, .share-2-of-N.txt, etc.
        Each file contains ONLY that person's share + instructions, so you can
        hand each file directly to the recipient without exposing other shares."""
        # Derive initial dir from the .qcx file when available (handles batch mode where
        # self._out may be stale or hidden); fall back to self._out for single-file mode.
        if qcx_path and os.path.isfile(qcx_path):
            out_dir = os.path.dirname(os.path.abspath(qcx_path))
        elif self._out.get().strip():
            out_dir = os.path.dirname(os.path.abspath(self._out.get().strip()))
        else:
            out_dir = ""
        folder = filedialog.askdirectory(
            initialdir=out_dir,
            title="Choose a folder to save individual share files")
        if not folder: return
        k = self._result_k or self._k.get()
        n = self._result_n or self._n.get()
        stem = os.path.splitext(orig)[0] if orig else "shares"
        # Compute fingerprint of the .qcx file so recipients can match their share
        if qcx_path is None:
            qcx_path = self._out.get().strip()
        # The guard is keyed by the output this run wrote (_done) or, for
        # callers that never named it, the legacy single-file token; clear
        # both so neither can stay armed forever.
        pending_tokens = {qcx_path, "__single__"}
        qcx_name = os.path.basename(qcx_path) if qcx_path else ""
        fingerprint = ""
        if qcx_path and os.path.isfile(qcx_path):
            try:
                import hashlib
                with open(qcx_path, "rb") as fh:
                    fingerprint = hashlib.sha256(fh.read(65536)).hexdigest()[:12]
            except Exception: pass
        mnemonics = _mnemonics_for(shares, k)
        saved, renamed = [], []
        try:
            # Collision handling is per run: every file of this set gets the
            # same stem (<stem>_2.share-i-of-n.txt), never a mix of two.
            fnames, run_renamed = _share_file_names(folder, stem, n)
            for i, s in enumerate(shares, 1):
                fname = fnames[i-1]
                mn = mnemonics[i-1] if i-1 < len(mnemonics) else None
                fp_line = (f"File fingerprint:  {fingerprint}...\n") if fingerprint else ""
                text = (
                    f"QuantaCrypt Share {i} of {n}\n"
                    f"{'='*60}\n"
                    f"Encrypted file:    {qcx_name}\n"
                    f"{fp_line}"
                    f"Threshold:         Any {k} of {n} shares are needed to decrypt\n"
                    f"{'='*60}\n\n"
                    f"This file contains one of the {n} keys to {qcx_name or 'the encrypted file'}. "
                    f"Either format below works. Use whichever is easier.\n\n"
                    f"KEEP THIS FILE PRIVATE. Do not share it with other shareholders.\n\n"
                    f"── QCSHARE- code (for copy-paste) ──────────────────────\n"
                    f"{s}\n\n"
                )
                if mn:
                    text += (
                        f"── 50-word mnemonic (for offline backup) ───────────────\n"
                        f"{mn}\n\n"
                    )
                text += (
                    f"── How to decrypt ───────────────────────────────────────\n"
                    f"1. Collect {k} share files from {k} of the {n} shareholders.\n"
                    f"2. Open quantacrypt and load the encrypted file.\n"
                    f"3. Paste each QCSHARE- code (or type the 50 words) into the\n"
                    f"   corresponding share slot.\n"
                    f"4. Click Decrypt.\n"
                )
                # 0600 + O_EXCL: an earlier run's share files with the same
                # stem are the only copies of ITS key — never replace them.
                written, was_renamed = write_new_private_file(fname, text)
                saved.append(written)
                if was_renamed:
                    renamed.append(os.path.basename(written))
        except OSError as e:
            opts = {"parent": self} if isinstance(self, tk.Misc) else {}
            messagebox.showerror("Save failed",
                f"Could not write share file:\n{e}\n\n"
                f"Saved {len(saved)} of {n} files before the error.", **opts)
            # Partial save: some recipients' files are missing, so this
            # file's shares stay pending (the leave-guard dialog still
            # offers "Leave anyway?" as the escape hatch).
            return
        self._shares_pending -= pending_tokens
        # Dim ShareCards (single-file mode — they live in self._results directly)
        if banner_frame is getattr(self, "_shares_warn", None):
            try:
                for w in self._results.winfo_children():
                    if isinstance(w, ShareCard):
                        w.mark_saved()
            except Exception: pass
        # Update the warning banner to show success.
        # banner_frame may be self._shares_warn (single-file) or a per-file sec frame (batch).
        target = banner_frame if banner_frame is not None else getattr(self, "_shares_warn", None)
        note = ("Each recipient gets their own file. Distribute one file per person.\n"
                "Recommended: test decryption before distributing.")
        if run_renamed or renamed:
            shown = [os.path.basename(p) for p in saved] if run_renamed else renamed
            note += ("\nShare files with that name already existed there, so these were saved as "
                     + ", ".join(shown) + ". The earlier files were left untouched.")
        EncryptorApp._show_saved_banner(
            self, target, f"{n} share files saved", os.path.basename(folder), note,
            saved[0] if saved else folder)

    def _show_saved_banner(self, target, title, where, note, reveal):
        """Turn a share banner into the green 'saved' state (one recipe for
        both save paths).  Silently no-ops on a stale/destroyed frame."""
        try:
            if not (target and target.winfo_exists()):
                return
            for w in target.winfo_children(): w.destroy()
            target.config(highlightbackground=C["success"])
            done_row = tk.Frame(target, bg=C["surface"])
            done_row.pack(fill="x", padx=SP["l"], pady=(SP["s"],SP["xs"]))
            tk.Label(done_row, text=f"{ICON['ok']}  {title}", font=F["body_b"],
                     bg=C["surface"], fg=C["success"]).pack(side="left")
            tk.Label(done_row, text=where, font=F["caption"],
                     bg=C["surface"], fg=C["text3"]).pack(side="right")
            tk.Label(target, text=note,
                     font=F["caption"], bg=C["surface"], fg=C["text3"],
                     anchor="w", justify="left").pack(fill="x", padx=SP["l"], pady=(0,SP["s"]))
            FlatButton(target, REVEAL_LABEL,
                       lambda: self._reveal_ui(reveal),
                       primary=False, small=True).pack(anchor="w", padx=SP["l"], pady=(0,SP["s"]))
        except Exception:
            pass

    def _save_shares(self, shares, orig, qcx_path=None):
        qcx_path = (qcx_path or self._out.get()).strip()
        out_dir = os.path.dirname(os.path.abspath(qcx_path)) if qcx_path else ""
        p=filedialog.asksaveasfilename(initialdir=out_dir,
            initialfile=os.path.splitext(orig)[0]+".shares.txt",defaultextension=".txt")
        if not p: return
        k = self._result_k or self._k.get()
        n = self._result_n or self._n.get()
        mnemonics = _mnemonics_for(shares, k)
        # Compute a short fingerprint of the .qcx file to help match shares to file later
        qcx_ref = ""
        if qcx_path and os.path.isfile(qcx_path):
            try:
                import hashlib
                with open(qcx_path, "rb") as fh:
                    digest = hashlib.sha256(fh.read(65536)).hexdigest()[:12]
                qcx_ref = f"\nFile:      {os.path.basename(qcx_path)}\nFingerprint (SHA-256 prefix): {digest}..."
            except Exception:
                qcx_ref = f"\nFile:      {os.path.basename(qcx_path)}"
        # Wrap the file write in try/except so a full disk or
        # permission error doesn't leave _shares_pending=True forever, trapping
        # the user in an unsaved-shares dialog they can never clear.
        text = f"QuantaCrypt Key Shares\nThreshold: {k} of {n}{qcx_ref}\n{'='*60}\n\n"
        for i,s in enumerate(shares,1):
            text += f"Share {i}, QCSHARE- code:\n{s}\n\n"
            mn=mnemonics[i-1]
            if mn: text += f"Share {i}, 50-word mnemonic:\n{mn}\n\n"
            text += "-"*60+"\n\n"
        try:
            # 0600 + O_EXCL — an existing file with that name is somebody's
            # only key material, so this goes to <stem>_2 instead.
            p, renamed = write_new_private_file(p, text)
        except OSError as _e:
            messagebox.showerror("Save failed",
                f"Could not write shares file:\n{_e}\n\n"
                "Your shares have NOT been saved. Please try a different location.",
                parent=self)
            return
        # Shares are now saved: this run's token, or the legacy one when the
        # caller did not name the output.
        self._shares_pending.discard(qcx_path or "__single__")
        self._shares_pending.discard("__single__")
        try:
            for w in self._results.winfo_children():
                if isinstance(w, ShareCard):
                    w.mark_saved()
        except Exception: pass
        note = "Recommended: test decryption with one share set before distributing."
        if renamed:
            note += (f"\nA file with that name already existed, so this one was saved as "
                     f"{os.path.basename(p)}. The earlier file was left untouched.")
        self._show_saved_banner(
            getattr(self, "_shares_warn", None), "Shares saved", os.path.basename(p), note, p)

def main(): EncryptorApp().mainloop()
if __name__=="__main__": main()
