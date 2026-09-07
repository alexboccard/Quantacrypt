#!/usr/bin/env python3
"""QuantaCrypt Decryptor — decryption GUI with password and Shamir modes."""
import os
import re
import shutil
import subprocess
import sys
import threading
import time as _time
import zipfile

import tkinter as tk
from tkinter import filedialog

from quantacrypt.core import crypto as cc
from quantacrypt.core import package as pkg
from quantacrypt.core.errors import CorruptPayload, classify_error
from quantacrypt.core.package import load_pkg  # noqa: F401  (re-exported for callers/tests)
from quantacrypt.core.crypto import MAGIC  # noqa: F401  (re-exported; tests compare it)
from quantacrypt.ui.shared import (
    C, F, SP, ICON, REVEAL_LABEL,
    accel, bind_shortcut, safe_after,
    styled_entry, bind_context_menu, fmt_size, rule, section_label,
    card, kv_row, confirm, alert, reveal_path, friendly_error,
    FlatButton, SegmentedControl, StagedProgressBar,
    FileCard, WizardSteps, RecentFiles, notify,
)

P = SP["xl"]  # outer page padding

# (friendly name, weight, keyword in the core.package progress message).
# One list per credential mode so no dot is ever skipped: a password file
# never "recovers" shares and a split-key file never runs Argon2id.
STAGES_SINGLE = [
    ("Verifying password",  0.55, "argon2id"),
    ("Loading key",         0.05, "kyber private key"),
    ("Unlocking",           0.15, "decapsulat"),
    ("Decrypting file",     0.25, "decrypting payload"),
]
STAGES_SHAMIR = [
    ("Recovering key",      0.15, "combining"),
    ("Loading key",         0.15, "kyber private key"),
    ("Unlocking",           0.30, "decapsulat"),
    ("Decrypting file",     0.40, "decrypting payload"),
]
STAGE_VERIFY  = ("Checking key", 0.15, "integrity")
STAGE_EXTRACT = [("Extracting folder", 1.0, "extracting")]
STAGES = STAGES_SINGLE  # backward-compatible alias

# "Extract folder" bounds — above these the user is asked first.
_EXTRACT_MAX_BYTES   = 4 << 30
_EXTRACT_MAX_ENTRIES = 100_000

# Copy that appears in more than one place — hoisted so the reset path can't
# drift from the initial build (it had: "Select an encrypted file" vs "...
# .qcx file", "output path" vs "output folder").
FILE_PROMPT     = "Select an encrypted .qcx file"
FILE_SUB_DROP   = "Click anywhere · .qcx is QuantaCrypt's encrypted format · or drag & drop"
FILE_SUB_NODROP = "Click anywhere · .qcx is QuantaCrypt's encrypted format"
SEC_HINT_EMPTY  = "Open a file to see how it's protected."
OUT_HINT_EMPTY  = "Open a file first to set the output folder."
OUT_HINT_LOADED = "Output folder. The original filename will be restored."
VERIFY_HELP     = ("Verify key only checks that your password or shares are right "
                   "without writing anything to disk.")
NO_RECOVERY_NOTE = "There is no way to recover this file without the password."

_WL = None
def get_wl():
    global _WL
    if _WL is None:
        from mnemonic import Mnemonic
        _WL = Mnemonic("english").wordlist
    return _WL

_MAX_SHARE_FILE = 1 << 20  # share .txt files are a few KB; refuse anything huge

def _stages_for(mode, verify=False):
    """Stage list for THIS run.  Verify swaps the payload stage for the
    first-chunk check, which is all it does."""
    stages = list(STAGES_SINGLE if mode == "single" else STAGES_SHAMIR)
    if verify:
        stages[-1] = STAGE_VERIFY
    return stages


def _find_stage(msg, stages=None):
    """Map a raw core progress string to (stage index, friendly label).
    The label is the stage name plus any NN% the core reported — the raw
    string itself ("Decrypting payload... 45%") is never shown."""
    low = (msg or "").lower()
    for i, (name, _, kw) in enumerate(stages or STAGES):
        if kw in low:
            m = re.search(r"(\d+)%", msg)
            return i, (f"{name}  {m.group(1)}%" if m else name)
    return None, None


def _zip_member_ok(name):
    """False for any archive path that could land outside the destination:
    absolute, drive-prefixed, or containing a '..' component."""
    n = (name or "").replace("\\", "/")
    if not n or n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        return False
    return ".." not in n.split("/")


def _makedirs_private(path):
    """``os.makedirs`` applies its mode to the leaf only, so an archive
    without directory entries would leave the intermediate folders at the
    umask.  Every level made here is 0700."""
    missing = []
    while not os.path.isdir(path):
        missing.append(path)
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    for p in reversed(missing):
        try:
            os.mkdir(p, 0o700)
        except FileExistsError:
            pass


def _open_file(path):
    """Open the decrypted file directly with the system default application."""
    try:
        if sys.platform == "darwin":
            # "--": a recovered name starting with a dash is not a flag.
            subprocess.run(["open", "--", path], check=False)
        elif sys.platform == "win32":
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            # xdg-open rejects "--"; an absolute path cannot start with a dash.
            subprocess.run(["xdg-open", os.path.abspath(path)], check=False)
    except Exception:
        pass


def _share_list(nums):
    """'Share 2' / 'Shares 1 and 3' / 'Shares 1, 2 and 4' — never a list repr."""
    nums = [str(n) for n in nums]
    if len(nums) == 1:
        return f"Share {nums[0]}"
    return "Shares " + ", ".join(nums[:-1]) + f" and {nums[-1]}"


def _extract_share_codes(text, wl=None):
    """Share extraction lives in core/package.py so both UIs agree."""
    from quantacrypt.core.package import extract_share_codes
    return extract_share_codes(text)


# ── WordEntry ─────────────────────────────────────────────────────────────────

class WordEntry(tk.Frame):
    MAX_DROP = 8

    def __init__(self, parent, number, wl, on_confirm=None, on_done=None,
                 on_change=None, **kw):
        super().__init__(parent, bg=C["surface2"],
                         highlightbackground=C["border"], highlightthickness=1, **kw)
        self._wl=wl; self._cb=on_confirm; self._done_cb=on_done; self._nxt=None
        self._chg=on_change   # fired on EVERY edit, so counters never go stale
        self._dd=None; self._lb=None; self._open=False
        tk.Label(self, text=f"{number:02d}", font=F["small"],
                 bg=C["surface2"], fg=C["text3"], width=2).pack(side="left", padx=(SP["xs"],0))
        self._v = tk.StringVar()
        self._v.trace_add("write", self._typed)
        self._e = tk.Entry(self, textvariable=self._v, font=F["mono_s"],
                           bg=C["surface2"], fg=C["text"],
                           insertbackground=C["accent_text"],
                           relief="flat", bd=0, highlightthickness=0, width=9)
        bind_context_menu(self._e)
        self._e.pack(side="left", fill="x", expand=True, ipady=SP["xs"], padx=(0,SP["xs"]))
        for ev,fn in [("<Down>",self._dn),("<Up>",self._up),("<Return>",self._ret),
                      ("<Tab>",self._tab),("<space>",self._spc),
                      ("<FocusOut>",self._fout),("<FocusIn>",self._fin),
                      ("<Escape>",self._esc)]:
            self._e.bind(ev, fn)

    def get(self): return self._v.get().strip().lower()
    def set(self, w): self._v.set(w); self._border()
    def focus(self): self._e.focus_set()
    def focus_force(self): self.winfo_toplevel().lift(); self._e.focus_force()
    def valid(self): return self.get() in self._wl
    def set_enabled(self, on):
        self._e.config(state="normal" if on else "disabled")

    def _esc(self, e):
        """Escape closes the autocomplete only.  It must swallow the event:
        letting it propagate reaches the window's Escape binding, which
        closes the decryptor and throws away every typed word."""
        if self._open or self._dd is not None:
            self._close()
            return "break"
        return None

    def _typed(self,*_):
        if self._chg: self._chg()
        t = self._v.get().strip().lower()
        if not t: self._close(); self._set_b(C["border"]); return
        m = [w for w in self._wl if w.startswith(t)]
        if not m: self._set_b(C["error"]); self._close(); return
        self._set_b(C["success"] if t in self._wl else C["accent_text"])
        if not (len(m)==1 and m[0]==t): self._show(m)
        else: self._close()

    def _fin(self,e):
        t = self._v.get().strip().lower()
        if t and t not in self._wl:
            m = [w for w in self._wl if w.startswith(t)]
            if m: self._show(m)

    def _fout(self,e): self.after(150, self._hfo)
    def _hfo(self):
        try:
            if not self.winfo_exists(): return   # widget destroyed during the 150ms delay
        except Exception: return
        self._border()
        try:
            f = self.winfo_toplevel().focus_get()
            if f is not self._lb: self._close()
        except Exception: self._close()

    def _border(self):
        if self.valid(): self._set_b(C["success"])
        elif self.get(): self._set_b(C["error"])
        else: self._set_b(C["border"])

    def _dn(self,e):
        if not self._open:
            t = self._v.get().strip().lower()
            if t: self._show([w for w in self._wl if w.startswith(t)])
        if self._lb:
            self._lb.focus_set()
            if not self._lb.curselection(): self._lb.selection_set(0)
            self._lb.event_generate("<Down>")
        return "break"

    def _up(self,e):
        if self._lb and self._open: self._lb.focus_set(); self._lb.event_generate("<Up>")
        return "break"

    def _ret(self,e):
        if self._open and self._lb:
            s = self._lb.curselection()
            if s: self._sel(self._lb.get(s[0])); return "break"
        if self.valid(): self._next()
        return "break"

    def _tab(self,e):
        if self._open and self._lb:
            s = self._lb.curselection()
            if s: self._sel(self._lb.get(s[0])); return "break"
            if self._lb.size(): self._sel(self._lb.get(0)); return "break"
        self._close()
        if self.valid(): self._next()
        return "break"

    def _spc(self,e):
        if self._open and self._lb:
            s = self._lb.curselection()
            if s: self._sel(self._lb.get(s[0])); return "break"
            if self._lb.size(): self._sel(self._lb.get(0)); return "break"
        if self.valid(): self._next(); return "break"

    def _show(self, matches):
        if not matches: self._close(); return
        if self._dd is None:
            self._dd = tk.Toplevel(self)
            self._dd.transient(self.winfo_toplevel())
            self._dd.wm_overrideredirect(True)
            self._dd.wm_attributes("-topmost", True)
            self._dd.configure(bg=C["border"])
            fr = tk.Frame(self._dd, bg=C["surface"],
                          highlightbackground=C["accent_text"], highlightthickness=1)
            fr.pack(fill="both", expand=True, padx=1, pady=1)
            sb2 = tk.Scrollbar(fr, orient="vertical", bg=C["surface2"])
            self._lb = tk.Listbox(fr, yscrollcommand=sb2.set, font=F["mono_s"],
                                   bg=C["surface"], fg=C["text"],
                                   selectbackground=C["accent"],
                                   selectforeground=C["text"],
                                   activestyle="none", relief="flat", bd=0,
                                   highlightthickness=0, width=12)
            sb2.config(command=self._lb.yview)
            self._lb.pack(side="left", fill="both", expand=True)
            sb2.pack(side="right", fill="y")
            self._lb.bind("<Return>",          self._lbpick)
            self._lb.bind("<Double-1>",        self._lbpick)
            self._lb.bind("<ButtonRelease-1>", self._lbpick)
            self._lb.bind("<Tab>",             self._lbtab)
            self._lb.bind("<Escape>",          self._lbesc)
            self._lb.bind("<FocusOut>",        lambda e: self.after(120,self._mc))
        self._lb.delete(0,"end")
        show = matches[:30]
        for w in show: self._lb.insert("end",w)
        row_h = min(len(show), self.MAX_DROP)
        self._lb.config(height=row_h)
        self.update_idletasks()
        x   = self._e.winfo_rootx()
        ey  = self._e.winfo_rooty()
        eh  = self._e.winfo_height()
        # Estimate dropdown pixel height to check screen bounds
        # Listbox row height ≈ font size + 2px padding; approximate as 16px per row
        dd_h = row_h * 16 + 4
        screen_h = self.winfo_toplevel().winfo_screenheight()
        if ey + eh + dd_h > screen_h:
            # Flip above the entry widget
            y = ey - dd_h
        else:
            y = ey + eh
        self._dd.wm_geometry(f"+{x}+{y}")
        self._dd.deiconify(); self._open = True

    def _close(self, dest=True):
        self._open = False
        if self._dd: self._dd.withdraw()
        if dest and self._dd:
            try: self._dd.destroy()
            except Exception: pass
            self._dd = None; self._lb = None

    def _mc(self):
        try:
            f = self.winfo_toplevel().focus_get()
            if f not in (self._e, self._lb): self._close()
        except Exception: self._close()

    def _lbpick(self,e):
        s = self._lb.curselection()
        if s: self._sel(self._lb.get(s[0]))

    def _lbtab(self,e):
        s = self._lb.curselection()
        if s: self._sel(self._lb.get(s[0]))
        return "break"

    def _lbesc(self, e):
        self._close()
        try: self._e.focus_force()
        except Exception: pass
        return "break"

    def _sel(self, word):
        self._v.set(word); self._set_b(C["success"])
        self._close()
        self.winfo_toplevel().lift()
        self._e.focus_force()
        if self._cb: self._cb(word)
        self.after(50, self._next)

    def _next(self):
        if self._nxt: self._nxt.focus_force()
        elif self._done_cb: self._done_cb()

    def _set_b(self,c): self.config(highlightbackground=c, highlightthickness=1)


# ── MnemonicShareInput ────────────────────────────────────────────────────────

class MnemonicShareInput(tk.Frame):
    """Collapsible mnemonic share panel.  Share 1 starts expanded; others
    start collapsed so only the header/progress bar is visible.  Clicking the
    header row (or the chevron) toggles the 50-word grid open/closed; the
    header is also in the Tab order and toggles with Return / space."""

    def __init__(self, parent, num, wl, start_expanded=True,
                 on_change=None, on_done=None, **kw):
        super().__init__(parent, bg=C["bg"], **kw)
        self._wl=wl; self._cells=[]; self._expanded = start_expanded
        self._on_change = on_change
        self._last_n = -1
        self._upd_job = None   # pending after_idle → one refresh per burst of edits
        self._pbar_w = 0

        hdr = tk.Frame(self, bg=C["surface"],
                       highlightbackground=C["border"], highlightthickness=1,
                       cursor="hand2", takefocus=1)
        hdr.pack(fill="x", pady=(0,SP["s"]))
        self._hdr = hdr

        self._chevron = tk.Label(hdr, text=ICON["chevron_open"] if start_expanded else ICON["chevron_closed"],
                                  font=F["body_b"], bg=C["surface"], fg=C["text3"],
                                  cursor="hand2")
        self._chevron.pack(side="left", padx=(SP["s"],0), pady=SP["s"])

        left = tk.Frame(hdr, bg=C["surface"])
        left.pack(side="left", padx=(SP["s"],SP["l"]), pady=SP["s"])
        tk.Label(left, text=f"Share {num}", font=F["body_b"],
                 bg=C["surface"], fg=C["text"]).pack(anchor="w")
        self._count = tk.Label(left, text="0 / 50 words", font=F["caption"],
                                bg=C["surface"], fg=C["text3"])
        self._count.pack(anchor="w")

        self._btn_right = tk.Frame(hdr, bg=C["surface"])
        self._btn_right.pack(side="right", padx=SP["l"], pady=SP["s"])
        self._paste_btn = FlatButton(self._btn_right, "Paste", self._paste, primary=False, small=True)
        self._paste_btn.pack(side="right", padx=(SP["s"],0))
        self._clear_btn = FlatButton(self._btn_right, "Clear", self.clear,  primary=False, small=True)
        self._clear_btn.pack(side="right")

        self._pbar = tk.Canvas(hdr, height=2, bg=C["surface2"], highlightthickness=0)
        self._pbar.pack(fill="x", side="bottom")
        self._pbar.bind("<Configure>", lambda e: self._draw_pbar(e.width))

        for w in (hdr, self._chevron, left):
            w.bind("<Button-1>", lambda e: self.toggle())
        hdr.bind("<Return>", lambda e: self.toggle())
        hdr.bind("<space>",  lambda e: self.toggle())
        hdr.bind("<FocusIn>",  lambda e: hdr.config(highlightbackground=C["accent_text"], highlightthickness=2))
        hdr.bind("<FocusOut>", lambda e: hdr.config(highlightbackground=C["border"], highlightthickness=1))

        self._grid_frame = tk.Frame(self, bg=C["bg"])
        for c in range(10): self._grid_frame.columnconfigure(c, weight=1)

        for i in range(50):
            cell = WordEntry(self._grid_frame, i+1, wl, on_confirm=self._confirmed,
                             on_done=on_done if i == 49 else None,
                             on_change=self._schedule_upd)
            cell.grid(row=i//10, column=i%10, padx=2, pady=2, sticky="ew")
            self._cells.append(cell)
        for i in range(49):
            self._cells[i]._nxt = self._cells[i+1]

        if start_expanded:
            self._grid_frame.pack(fill="x")
        # (collapsed: grid_frame stays unpacked until toggle)

        self._upd()

    def toggle(self):
        """Expand or collapse the word-entry grid."""
        self._expanded = not self._expanded
        if self._expanded:
            self._grid_frame.pack(fill="x")
            self._chevron.config(text=ICON["chevron_open"])
        else:
            self._grid_frame.pack_forget()
            self._chevron.config(text=ICON["chevron_closed"])

    def expand(self):
        if not self._expanded: self.toggle()

    def collapse(self):
        if self._expanded: self.toggle()

    def get_mnemonic(self): return " ".join(c.get() for c in self._cells)
    def is_complete(self): return all(c.valid() for c in self._cells)
    def valid_count(self): return sum(1 for c in self._cells if c.valid())
    def has_input(self): return any(c.get() for c in self._cells)
    def focus(self):
        """Expand first so cells are visible before giving focus."""
        self.expand()
        if self._cells: self._cells[0].focus()
    def set_words(self, words):
        for cell, word in zip(self._cells, words): cell.set(word.lower())
        self._upd()
    def set_enabled(self, on):
        for c in self._cells: c.set_enabled(on)
        self._paste_btn.enable(on); self._clear_btn.enable(on)
        self._hdr.config(takefocus=1 if on else 0)
    def clear(self):
        for c in self._cells: c.set("")
        self._upd()
    def _confirmed(self,_): self._upd()

    def _schedule_upd(self):
        """Every WordEntry edit lands here; one after_idle refresh per burst
        (set_words fires 50 edits) keeps the counter exact without polling."""
        if self._upd_job is None:
            try:
                self._upd_job = self.after_idle(self._upd)
            except tk.TclError:
                pass

    def _draw_pbar(self, w=None):
        if w is not None: self._pbar_w = w
        w = self._pbar_w
        if w <= 1: return
        n = self.valid_count()
        col = C["success"] if n==50 else (C["warning"] if n>=25 else C["accent_text"])
        self._pbar.delete("all")
        f = int(w*n/50)
        if f: self._pbar.create_rectangle(0,0,f,2, fill=col, outline="")

    def _upd(self):
        self._upd_job = None
        try:
            if not self.winfo_exists(): return
        except Exception: return
        n = self.valid_count()
        glyph = f"  {ICON['ok']}" if n == 50 else ""
        self._count.config(
            text=f"{n} / 50 words{glyph}",
            fg=C["success"] if n==50 else (C["warning"] if n>0 else C["text3"]))
        self._draw_pbar()
        if n != self._last_n:
            self._last_n = n
            if self._on_change: self._on_change()

    def _paste(self):
        top = self.winfo_toplevel()
        try: text = self.clipboard_get()
        except Exception: alert(top, "Nothing to paste", "The clipboard is empty."); return
        if text.strip().startswith("QCSHARE-"):
            alert(top, "That's a code share",
                  "This share starts with QCSHARE-, so it's a code share. "
                  "Switch to \"QCSHARE- codes\" above and paste it there instead.")
            return
        words = text.strip().split()
        if len(words) != 50:
            alert(top, "Wrong length", f"A share phrase has 50 words; the clipboard has {len(words)}.")
            return
        bad = [w for w in words if w.lower() not in self._wl]
        if bad and not confirm(top, "Unknown words",
                               f"{len(bad)} word(s) aren't in the share word list: "
                               f"{', '.join(bad[:3])}.\nFill the grid anyway?",
                               yes="Fill anyway", no="Cancel"):
            return
        self.set_words(words)


# ── FileInfoCard ──────────────────────────────────────────────────────────────

def _protection_label(meta):
    """Plain-language 'how is this file protected' string used by both cards."""
    mode = meta.get("mode", "?")
    if mode == "single":
        return "A password"
    if mode == "shamir":
        return (f"A split key. Any {meta.get('threshold','?')} of "
                f"{meta.get('total','?')} shares unlock it")
    return str(mode)


class FileInfoCard(tk.Frame):
    """Shows file metadata including encrypted-at date and original size."""
    def __init__(self, parent, meta, orig, sz=0, ts=0, **kw):
        super().__init__(parent, bg=C["surface"],
                         highlightbackground=C["border"], highlightthickness=1, **kw)
        inner = tk.Frame(self, bg=C["surface"])
        inner.pack(fill="x", padx=SP["l"], pady=SP["s"])
        # Filename is always inside the encrypted payload (revealed after decryption).
        file_label = orig if orig else "Hidden; shown after decryption"
        rows = [
            ("File",        file_label),
            ("Protected by", _protection_label(meta)),
            ("Encryption",  "Quantum-resistant (AES-256-GCM + ML-KEM)"),
        ]
        # Show original size and encryption date if available
        if sz: rows.append(("Original size", fmt_size(sz)))
        if ts:
            try:
                rows.append(("Encrypted on", _time.strftime("%Y-%m-%d %H:%M", _time.localtime(ts))))
            except Exception: pass
        for lbl, val in rows:
            kv_row(inner, lbl, val, label_width=12)


# ── Main App ──────────────────────────────────────────────────────────────────

# DnD support — works when the root Tk was created as TkinterDnD.Tk
try:
    from tkinterdnd2 import DND_FILES as _DND_FILES
except ImportError:
    _DND_FILES = None


class _Tooltip:
    """Minimal hover tooltip for Tkinter widgets.
    Usage: _Tooltip(widget, "text")
    Hover-only help is invisible to keyboard users, so callers should also
    render the same text as a visible caption."""
    def __init__(self, widget, text):
        self._widget = widget; self._text = text; self._tip = None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")

    def _show(self, event=None):
        if self._tip: return
        try:
            x = self._widget.winfo_rootx() + self._widget.winfo_width() // 2
            y = self._widget.winfo_rooty() - 28
            self._tip = tip = tk.Toplevel(self._widget)
            tip.wm_overrideredirect(True)
            tip.wm_geometry(f"+{x}+{y}")
            tip.configure(bg=C["surface2"])
            tk.Label(tip, text=self._text, font=F["small"],
                     bg=C["surface2"], fg=C["text2"],
                     padx=SP["s"], pady=SP["xs"]).pack()
        except Exception: self._tip = None

    def _hide(self, event=None):
        try:
            if self._tip: self._tip.destroy()
        except Exception: pass
        self._tip = None


def _section(parent, text):
    """Section heading; returns the text label so the Secret section can be
    relabelled PASSWORD / SHARES per file."""
    return section_label(parent, text, padx=P)


class DecryptorApp(tk.Toplevel):
    STEPS = ["File", "Secret", "Decrypt"]

    def __init__(self, master=None, payload=None, qcx_path=None, on_close=None, center_at=None):
        super().__init__(master)
        self.title("QuantaCrypt · Decrypt")
        self.configure(bg=C["bg"])
        self.resizable(True, True)
        self.geometry("620x780")
        self.minsize(560, 560)

        self._payload  = payload
        self._qcx_path = qcx_path
        self._meta     = payload["meta"] if payload else None
        self._orig     = None
        self._sz       = 0   # Original size (known after decryption)
        self._ts       = 0   # Encryption timestamp (known after decryption)
        self._mode_val = self._meta["mode"] if self._meta else None
        self._busy     = False
        self._verifying = False  # which flow the worker is running (for cancel copy)
        self._extracting = False
        self._cancel   = False   # signals worker thread to abort
        self._close_pending = False  # close requested while a worker runs
        self._finished_ok = False    # worker wrote output after a close request
        self._run_stages = list(STAGES)
        self._imode    = tk.StringVar(value="mnemonic")
        self._inputs   = []      # MnemonicShareInput panels (mnemonic mode)
        self._entries  = []      # QCSHARE- entries (raw mode)
        self._entry_marks = []   # validity glyph labels beside each raw entry
        self._share_btns  = []   # Paste / Paste all / Load / Add buttons (frozen during decrypt)
        self._add_btn     = None
        self._pw_failures = 0
        self._on_close = on_close
        self._imode_trace_id = None  # set in _load_payload when shamir mode is active
        # Always wire WM_DELETE_WINDOW so closing while busy is handled safely
        self.protocol("WM_DELETE_WINDOW", self._maybe_close)

        self._build()
        self._center(center_at=center_at)
        self.update()  # macOS: force canvas embedded-window Configure event so form renders
        if self._payload and qcx_path:
            self._file_card.load(qcx_path)
            self._load_payload()
        elif self._payload:
            self._load_payload()

        # Register drag-and-drop (only works when base class is TkinterDnD.Tk)
        drop_ok = False
        if _DND_FILES:
            try:
                self.drop_target_register(_DND_FILES)
                self.dnd_bind("<<Drop>>", self._on_drop)
                drop_ok = True
            except Exception:
                pass
        # Only promise "drag & drop" when a drop target actually registered
        self._file_card.set_drop_supported(drop_ok, FILE_SUB_DROP, FILE_SUB_NODROP)

        def _open_shortcut():
            if self._busy:
                self._flash_busy()
            else:
                self._file_card._pick()
        def _decrypt_shortcut():
            if self._busy:
                self._flash_busy()
            else:
                self._start()
        bind_shortcut(self, "o", _open_shortcut)
        bind_shortcut(self, "Return", _decrypt_shortcut)
        self.bind("<Escape>", self._on_escape)

    # ── Status line ───────────────────────────────────────────────────────────

    def _set_status(self, msg, detail=""):
        """Neutral progress / info text (grey)."""
        self._err.config(text=msg, fg=C["text3"])
        self._err_detail.config(text=detail)

    def _set_error(self, msg, detail=""):
        """Something went wrong (red).  ``detail`` is the technical second line."""
        self._err.config(text=msg, fg=C["error"])
        self._err_detail.config(text=detail)

    def _flash_busy(self):
        self._set_status("Busy. Please wait for decryption to finish")
        self.after(2000, lambda: self._set_status("")
                   if self._err.cget("text").startswith("Busy") else None)

    # ── Close / Escape ────────────────────────────────────────────────────────

    def _has_typed_input(self):
        if self._mode_val == "single" and hasattr(self, "_pw"):
            try:
                if self._pw.get(): return True
            except Exception: pass
        if any(inp.has_input() for inp in self._inputs): return True
        return any(e.get().strip() for e in self._entries)

    def _on_escape(self, e=None):
        self._maybe_close()
        return "break"

    def _maybe_close(self):
        """Close guard: while running, Escape is a cancel request; with a
        password or shares typed but unused, ask first; otherwise close."""
        if self._busy:
            self._close()
            return
        if self._has_typed_input():
            if not confirm(self, "Discard what you typed?",
                           "Your password or shares haven't been used yet. "
                           "Closing this window throws them away.",
                           yes="Discard", no="Keep editing", danger=True):
                return
        self._close()

    def can_quit(self) -> bool:
        """The Quit Apple event's guard (``__main__._register_quit``).  A
        running worker cannot be waited for from there: say so and refuse."""
        if self._busy:
            self._set_status("Decryption in progress. Cancel it (Esc) or let it finish, then quit.")
            return False
        return not self._has_typed_input() or confirm(
            self, "Discard what you typed?",
            "Your password or shares haven't been used yet. "
            "Closing this window throws them away.",
            yes="Discard", no="Keep editing", danger=True)

    def _close(self):
        if self._busy:
            # Never destroy the window under a running worker: Argon2id
            # can't be interrupted and may outlast any fixed timeout, and a
            # worker that passes its cancel checks still writes the file.
            # Ask it to stop and close only once it has actually returned.
            if not self._close_pending:
                self._close_pending = True
                self._cancel = True
                try: self._cancel_btn.enable(False)
                except Exception: pass
                self._set_status("Cancelling. This window closes when the current step finishes…")
                self._poll_close()
            return
        self.destroy()
        if self._on_close:
            self._on_close()
        else:
            self.master.destroy()  # no launcher — quit app

    def _poll_close(self):
        """Wait for the worker to return, then close — unless it finished
        and wrote a file, in which case the result card must stay visible."""
        try:
            if not self.winfo_exists(): return
        except Exception: return
        if self._busy:
            self.after(100, self._poll_close)
            return
        self._close_pending = False
        if self._finished_ok:
            self._finished_ok = False
            self._set_status("Finished before it could be cancelled. See the result below.")
            return
        self._close()

    def _after(self, fn, delay=0):
        """Worker → main-thread hop that tolerates a closed window."""
        safe_after(self, fn, delay)

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
        """Handle drag-and-drop .qcx file."""
        if self._busy:
            self._flash_busy()
            return
        # TkDnD braces only paths containing spaces, so "/a/x.qcx /a/y.qcx"
        # is two items — let Tcl split the list (same as the encryptor).
        try:
            parts = [p for p in self.tk.splitlist(event.data) if p]
        except Exception:
            raw = event.data.strip()
            if raw.startswith("{") and raw.endswith("}"): raw = raw[1:-1]
            parts = raw.split("} {")
        path = parts[0] if parts else ""
        if os.path.isdir(path):
            self._set_error("That's a folder. Drop a single .qcx file instead.")
            return
        if not os.path.isfile(path):
            self._set_error("Nothing usable was dropped. Drop a .qcx file, or click the box to choose one.")
            return
        if len(parts) > 1:
            self._set_status(f"Only one file can be decrypted at a time, so using {os.path.basename(path)}.")
        self._file_card.load(path)
        self._on_file(path)

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        hdr = tk.Frame(self, bg=C["bg"])
        hdr.pack(fill="x", padx=P, pady=(SP["l"],0))
        tk.Label(hdr, text="QuantaCrypt", font=F["display"],
                 bg=C["bg"], fg=C["text"]).pack(side="left")
        tk.Label(hdr, text="Decrypt", font=F["heading"],
                 bg=C["bg"], fg=C["text3"]).pack(side="left", padx=(SP["s"],0), pady=SP["xs"])
        if self._on_close:
            FlatButton(hdr, f"{ICON['back']} Home", self._maybe_close,
                       primary=False, small=True).pack(side="right")
        self._wiz = WizardSteps(self, self.STEPS)
        self._wiz.pack(fill="x", padx=P, pady=(SP["m"],0))
        rule(self, pady=0)

        outer = tk.Frame(self, bg=C["bg"]); outer.pack(fill="both", expand=True)
        cv = tk.Canvas(outer, bg=C["bg"], bd=0, highlightthickness=0)
        vsb = tk.Scrollbar(outer, orient="vertical", command=cv.yview)
        cv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y"); cv.pack(side="left", fill="both", expand=True)
        self._body = b = tk.Frame(cv, bg=C["bg"])
        self._cv = cv  # store for scroll-to-top on reset
        wid = cv.create_window((0,0), window=b, anchor="nw")
        b.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(wid, width=e.width))
        # Focus-aware scroll: only scroll this canvas when focus is not in a Toplevel dropdown
        def _scroll(delta):
            fw = self.focus_get()
            if fw and fw.winfo_toplevel() is not self: return
            cv.yview_scroll(delta, "units")
        # Bound on THIS toplevel (every descendant carries it in its bindtags),
        # not bind_all: a root-wide binding outlives the window and the two
        # wizards would replace each other's handler.
        self.bind("<MouseWheel>", lambda e: _scroll(int(-e.delta)))

        # 1. File — uses shared FileCard from shared_ui
        _section(b, "1  FILE")
        self._file_card = FileCard(b, self._on_file,
                                   prompt=FILE_PROMPT,
                                   sub=FILE_SUB_DROP,
                                   filetypes=[("QuantaCrypt","*.qcx"),("All files","*")])
        self._file_card.pack(fill="x", padx=P)
        self._info_wrap = tk.Frame(b, bg=C["bg"])
        self._info_wrap.pack(fill="x", padx=P, pady=(SP["s"],0))
        # Inspect button — shown after file load, reveals public metadata
        self._inspect_row = tk.Frame(b, bg=C["bg"])
        self._inspect_row.pack(fill="x", padx=P, pady=(SP["xs"],0))

        # 2. Password / Shares — relabelled per file in _load_payload
        self._sec_label = _section(b, "2  PASSWORD")
        self._sec_wrap = tk.Frame(b, bg=C["bg"])
        self._sec_wrap.pack(fill="x", padx=P)
        tk.Label(self._sec_wrap, text=SEC_HINT_EMPTY,
                 font=F["caption"], bg=C["bg"], fg=C["text3"]).pack(anchor="w")

        # 3. Decrypt — output folder + the action row
        _section(b, "3  DECRYPT")
        tk.Label(b, text="Save to", font=F["caption"], bg=C["bg"], fg=C["text3"],
                 anchor="w").pack(fill="x", padx=P, pady=(0,SP["xs"]))
        out_row = tk.Frame(b, bg=C["bg"]); out_row.pack(fill="x", padx=P)
        self._out = styled_entry(out_row)
        self._out.pack(side="left", fill="x", expand=True, ipady=SP["s"], ipadx=SP["s"])
        self._browse_btn = FlatButton(out_row, "Choose…", self._browse_out, primary=False, small=True)
        self._browse_btn.pack(side="left", padx=(SP["s"],0))
        self._out_hint = tk.Label(b, text=OUT_HINT_EMPTY,
                                   font=F["caption"], bg=C["bg"], fg=C["text3"], anchor="w")
        self._out_hint.pack(fill="x", padx=P, pady=(SP["xs"],0))

        act = tk.Frame(b, bg=C["bg"]); act.pack(fill="x", padx=P, pady=(SP["l"],SP["xs"]))
        self._btn = FlatButton(act, f"Decrypt file {ICON['arrow']}", self._start)
        self._btn.pack(side="left")
        self._btn.enable(False)   # enabled once a file is loaded
        # Verify: check key is correct without writing any output to disk
        self._verify_btn = FlatButton(act, "Verify key only", self._start_verify,
                                       primary=False, small=True)
        self._verify_btn.pack(side="left", padx=(SP["s"],0))
        self._verify_btn.enable(False)   # enabled once a file is loaded
        # Hover tooltip AND a visible caption — hover-only help never reaches
        # keyboard users.
        _Tooltip(self._verify_btn, VERIFY_HELP)
        tk.Label(b, text=VERIFY_HELP, font=F["small"], bg=C["bg"], fg=C["text3"],
                 anchor="w", justify="left", wraplength=490).pack(fill="x", padx=P)
        self._err = tk.Label(b, text="", font=F["caption"], bg=C["bg"], fg=C["error"],
                             anchor="w", justify="left", wraplength=490)
        self._err.pack(fill="x", padx=P, pady=(SP["s"],0))
        self._err_detail = tk.Label(b, text="", font=F["small"], bg=C["bg"], fg=C["text3"],
                                    anchor="w", justify="left", wraplength=490)
        self._err_detail.pack(fill="x", padx=P, pady=(0,SP["s"]))

        # Placeholder bar; every run builds its own (see _new_prog) so the
        # stage dots match what will actually happen.
        self._prog = StagedProgressBar(b, [(n,w) for n,w,_ in STAGES])
        # Cancel button row shown alongside the progress bar while busy.
        self._cancel_row = tk.Frame(b, bg=C["bg"])
        self._cancel_btn = FlatButton(
            self._cancel_row, "Cancel", self._request_cancel,
            primary=False, small=True,
        )
        self._cancel_btn.pack(side="right")
        self._results = tk.Frame(b, bg=C["bg"]); self._results.pack(fill="x", padx=P)
        # keyboard shortcut hint
        tk.Label(b, text=f"{accel('O')}  Open file  ·  {accel('↵')}  Decrypt  ·  Esc  Close",
                 font=F["small"], bg=C["bg"], fg=C["text3"]).pack(pady=(SP["s"],0))
        tk.Frame(b, bg=C["bg"], height=SP["l"]).pack()

    # ── File loading ──────────────────────────────────────────────────────────

    def _on_file(self, path):
        """Load a .qcx; our own ValueErrors become one plain sentence plus a
        technical second line, OS errors are masked."""
        self._set_status("")
        try:
            pkg = load_pkg(path)
            self._payload  = pkg
            self._meta     = pkg["meta"]
            self._orig     = None
            self._mode_val = self._meta["mode"]
            self._qcx_path = path  # Keep in sync so _run decrypts the right file
            self._pw_failures = 0
            self._load_payload(path)
            self.title(f"{os.path.basename(path)} — QuantaCrypt · Decrypt")
        except ValueError as e:
            self._forget_file()
            msg = str(e)
            low = msg.lower()
            if "not a quantacrypt" in low:
                self._set_error("This isn't a QuantaCrypt .qcx file. Choose a file that "
                                "QuantaCrypt encrypted.")
            elif "newer version" in low or "older format" in low:
                self._set_error(friendly_error(e))
            else:
                self._set_error("This .qcx file is damaged and can't be read.", msg)
        except Exception as e:
            # OS/IO errors — don't expose paths or internals
            self._forget_file()
            self._set_error("Couldn't open that file.", friendly_error(e))

    def _forget_file(self):
        """A file that failed to load must not leave the previous one armed
        behind a card that already shows the new name: Decrypt would run
        against the old file with credentials typed for the one on screen
        (run 18 F-206).  The whole screen goes back to "open a file" — the
        card's tick, the action buttons, the credential row and the output
        folder all belonged to the previous file (run 19 F-101)."""
        self._qcx_path = None
        self._reset()
        self._btn.enable(False)

    def _load_payload(self, path=None):
        for w in self._info_wrap.winfo_children(): w.destroy()
        # Show metadata — sz/ts not yet known (revealed after decryption)
        FileInfoCard(self._info_wrap, self._meta, self._orig,
                     sz=self._sz, ts=self._ts).pack(fill="x")

        if path or self._qcx_path:
            qcx = path or self._qcx_path
            # Suggest the same folder the .qcx lives in; the original filename
            # is sealed inside the payload and restored automatically after decryption.
            suggested_dir = os.path.dirname(os.path.abspath(qcx))
            if path or not self._out.get().strip():
                self._out.delete(0,"end"); self._out.insert(0, suggested_dir)
            self._out_hint.config(text=OUT_HINT_LOADED)

        # Refresh inspect button row — make it discoverable
        for w in self._inspect_row.winfo_children(): w.destroy()
        FlatButton(self._inspect_row, "View file details", self._show_inspect,
                   primary=False, small=True).pack(side="left")
        tk.Label(self._inspect_row, text="(no password needed)",
                 font=F["small"], bg=C["bg"], fg=C["text3"]).pack(side="left", padx=(SP["s"], 0))

        # Enable action buttons now that a valid file is loaded
        self._btn.enable(True)
        self._btn.config(text=f"Decrypt file {ICON['arrow']}")  # Restore action label
        self._verify_btn.enable(True)

        for w in self._sec_wrap.winfo_children(): w.destroy()
        self._inputs=[]; self._entries=[]; self._entry_marks=[]; self._share_btns=[]
        self._add_btn = None
        self._wiz.set_step(1)

        if self._mode_val == "single":
            self._sec_label.config(text="2  PASSWORD")
            tk.Label(self._sec_wrap, text="Password", font=F["caption"],
                     bg=C["bg"], fg=C["text3"]).pack(anchor="w", pady=(0,SP["xs"]))
            # Password row with per-field show/hide toggle
            pw_row = tk.Frame(self._sec_wrap, bg=C["bg"])
            pw_row.pack(fill="x")
            self._pw = styled_entry(pw_row, show="•")
            self._pw.pack(side="left", fill="x", expand=True, ipady=SP["s"], ipadx=SP["s"])
            self._eye_btn = FlatButton(pw_row, "Show", self._toggle_pw, primary=False, small=True)
            self._eye_btn.pack(side="left", padx=(SP["xs"],0))
            self._pw.bind("<Return>", lambda e: self._start())
            self._pw.focus()
        else:
            self._sec_label.config(text="2  SHARES")
            k=self._meta.get("threshold", 2); n=self._meta.get("total", k)
            tk.Label(self._sec_wrap,
                     text=f"Enter any {k} of the {n} shares to unlock this file.",
                     font=F["caption"], bg=C["bg"], fg=C["text3"]).pack(anchor="w", pady=(0,SP["s"]))
            # Remove stale trace from previous file load before _imode.set
            # (which fires all live traces against the destroyed _inputs_frame)
            if self._imode_trace_id:
                try: self._imode.trace_remove("write", self._imode_trace_id)
                except Exception: pass
                self._imode_trace_id = None
            self._imode.set("mnemonic")
            SegmentedControl(self._sec_wrap,
                [("mnemonic","50-word phrases"), ("raw","QCSHARE- codes")],
                self._imode).pack(fill="x", pady=(0,SP["s"]))
            self._imode_trace_id = self._imode.trace_add("write", lambda *_: self._rebuild_inputs())
            self._inputs_frame = tk.Frame(self._sec_wrap, bg=C["bg"])
            self._inputs_frame.pack(fill="x")
            self._build_share_inputs(k)

    def _show_inspect(self):
        """Show a popup with public metadata from the .qcx file (no key required)."""
        if not self._meta or not self._qcx_path:
            return
        meta = self._meta
        import hashlib

        # Compute file fingerprint
        fp = ""
        try:
            with open(self._qcx_path, "rb") as fh:
                fp = hashlib.sha256(fh.read(65536)).hexdigest()[:16]
        except Exception:
            pass
        try:
            file_size = fmt_size(os.path.getsize(self._qcx_path))
        except OSError:
            file_size = "unknown"

        mode = meta.get("mode", "?")
        if mode == "shamir":
            k, n = meta.get("threshold", "?"), meta.get("total", "?")
            protect = (f"A split key. Any {k} of {n} shares unlock it "
                       f"(Shamir secret sharing)")
        else:
            protect = "A password, slowed down against guessing (Argon2id)"
        version = meta.get("version", "?")

        # Build popup
        win = tk.Toplevel(self)
        win.title("File details")
        win.configure(bg=C["bg"])
        win.resizable(False, False)
        win.transient(self)
        win.grab_set()

        P2 = SP["xl"] - SP["xs"]
        tk.Label(win, text="File details", font=F["heading"],
                 bg=C["bg"], fg=C["text"]).pack(anchor="w", padx=P2, pady=(SP["l"],SP["xs"]))
        tk.Label(win, text=os.path.basename(self._qcx_path), font=F["mono"],
                 bg=C["bg"], fg=C["text2"]).pack(anchor="w", padx=P2, pady=(0,SP["s"]))

        body = card(win, padx=SP["l"], pady=SP["s"])
        body.outer.pack(fill="x", padx=P2, pady=(0,SP["xs"]))
        kv_row(body, "File size",    file_size, label_width=12, wraplength=320)
        kv_row(body, "Protected by", protect, label_width=12, wraplength=320)
        kv_row(body, "Encryption",   "Quantum-resistant (AES-256-GCM + ML-KEM)",
               label_width=12, wraplength=320)
        kv_row(body, "Format",       f"QuantaCrypt file format v{version}",
               label_width=12, wraplength=320)
        if fp:
            kv_row(body, "Fingerprint", f"{fp}…  (first 64 KB, SHA-256)",
                   label_width=12, wraplength=320)
        tk.Label(win,
                 text="The original filename and size are encrypted too.\n"
                      "they're revealed only after a successful decryption.",
                 font=F["small"], bg=C["bg"], fg=C["text3"],
                 justify="left").pack(anchor="w", padx=P2, pady=(SP["s"],0))

        close_btn = FlatButton(win, "Close", win.destroy, primary=False, small=True)
        close_btn.pack(anchor="e", padx=P2, pady=(SP["m"],SP["l"]))
        win.bind("<Escape>", lambda e: win.destroy())

        # Centre over parent
        win.update_idletasks()
        pw, ph = self.winfo_x(), self.winfo_y()
        ww, wh = self.winfo_width(), self.winfo_height()
        dw, dh = win.winfo_width(), win.winfo_height()
        win.geometry(f"+{pw+(ww-dw)//2}+{ph+(wh-dh)//2}")
        close_btn.focus_set()

    def _toggle_pw(self):
        """Toggle password field visibility with text button."""
        if not hasattr(self, "_pw"): return
        vis = self._pw.cget("show") == "•"
        self._pw.config(show="" if vis else "•")
        if hasattr(self, "_eye_btn"):
            self._eye_btn.config(text="Hide" if vis else "Show")

    # ── Share inputs ──────────────────────────────────────────────────────────

    def _build_share_inputs(self, k):
        for w in self._inputs_frame.winfo_children(): w.destroy()
        self._inputs=[]; self._entries=[]; self._entry_marks=[]; self._share_btns=[]
        self._add_btn = None
        n = self._meta.get("total", k) if self._meta else k
        # Header row: "N of k shares complete" counter + bulk-entry buttons
        hdr_row = tk.Frame(self._inputs_frame, bg=C["bg"])
        hdr_row.pack(fill="x", pady=(0,SP["s"]))
        self._share_counter = tk.Label(hdr_row, text="", font=F["caption"],
                                       bg=C["bg"], fg=C["text3"])
        self._share_counter.pack(side="left")
        b = FlatButton(hdr_row, "Load from file…", self._load_shares_from_files,
                       primary=False, small=True)
        b.pack(side="right"); self._share_btns.append(b)
        b = FlatButton(hdr_row, "Paste all", self._paste_all_shares,
                       primary=False, small=True)
        b.pack(side="right", padx=(0,SP["s"])); self._share_btns.append(b)
        _Tooltip(self._share_btns[0], "Open the .share-N-of-M.txt files the encryptor saved")

        self._slots_frame = tk.Frame(self._inputs_frame, bg=C["bg"])
        self._slots_frame.pack(fill="x")
        for i in range(k):
            self._add_share_slot(start_expanded=(i == 0))

        # Extra slot: when one share turns out to be wrong, add a spare instead
        # of clearing a good one.  The first k valid shares are used.
        add_row = tk.Frame(self._inputs_frame, bg=C["bg"])
        add_row.pack(fill="x", pady=(0,SP["s"]))
        self._add_btn = FlatButton(add_row, "+ Add another share",
                                   lambda: self._add_share_slot(focus=True),
                                   primary=False, small=True)
        self._add_btn.pack(side="left"); self._share_btns.append(self._add_btn)
        self._add_hint = tk.Label(add_row, text="", font=F["small"], bg=C["bg"], fg=C["text3"])
        self._add_hint.pack(side="left", padx=(SP["s"],0))
        self._refresh_add_btn()
        self._update_share_counter()

        if self._inputs: self._inputs[0].focus()
        elif self._entries: self._entries[0].focus()

    def _slot_count(self):
        return len(self._inputs) if self._imode.get() == "mnemonic" else len(self._entries)

    def _refresh_add_btn(self):
        if not getattr(self, "_add_btn", None): return
        n = self._meta.get("total", 0) if self._meta else 0
        at_max = self._slot_count() >= n
        try:
            self._add_btn.enable(not at_max and not self._busy)
            self._add_hint.config(text=f"This file was split into {n} shares." if at_max else "")
        except tk.TclError:
            self._add_btn = None  # widget was destroyed by a rebuild

    def _add_share_slot(self, start_expanded=True, focus=False):
        """Append one more share input (mnemonic panel or QCSHARE- row).
        ``focus`` moves the cursor into it (the "+ Add another share" button)."""
        idx = self._slot_count()
        n = self._meta.get("total", 0) if self._meta else 0
        if n and idx >= n:
            return
        if self._imode.get() == "mnemonic":
            wl = get_wl()
            inp = MnemonicShareInput(self._slots_frame, idx+1, wl,
                                     start_expanded=start_expanded,
                                     on_change=self._update_share_counter,
                                     on_done=lambda i=idx: self._share_done(i))
            inp.pack(fill="x", pady=(0,SP["m"]))
            self._inputs.append(inp)
            if focus: inp.focus()
        else:
            row = tk.Frame(self._slots_frame, bg=C["bg"])
            row.pack(fill="x", pady=(0,SP["s"]))
            tk.Label(row, text=f"Share {idx+1}", font=F["caption"],
                     bg=C["bg"], fg=C["text3"], width=9, anchor="w").pack(side="left")
            e = styled_entry(row)
            e.pack(side="left", fill="x", expand=True, ipady=SP["s"], ipadx=SP["s"])
            # Validity glyph beside the field — colour alone isn't enough
            mark = tk.Label(row, text="", font=F["caption"], bg=C["bg"], fg=C["text3"], width=2)
            mark.pack(side="left", padx=(SP["xs"],0))
            self._entries.append(e); self._entry_marks.append(mark)
            def _on_share_key(ev, entry=e):
                self._mark_entry(entry)
                self._update_share_counter()
            e.bind("<KeyRelease>", _on_share_key)
            # <<Paste>> fires before text lands; schedule validation 10ms later
            e.bind("<<Paste>>", lambda ev: self.after(10, _on_share_key, None))
            e.bind("<Return>", lambda ev, i=idx: self._share_done(i))
            def _paste_one(entry=e):
                self._paste_single_share(entry)
            pb = FlatButton(row, "Paste", _paste_one, primary=False, small=True)
            pb.pack(side="left", padx=(SP["xs"],0)); self._share_btns.append(pb)
            if focus: e.focus_set()
        self._refresh_add_btn()

    def _mark_entry(self, entry):
        """Colour + glyph for one QCSHARE- entry."""
        try: i = self._entries.index(entry)
        except ValueError: return
        val = entry.get().strip()
        mark = self._entry_marks[i]
        if not val:
            entry.config(highlightbackground=C["border"]); mark.config(text="")
        elif val.startswith("QCSHARE-"):
            entry.config(highlightbackground=C["success"]); mark.config(text=ICON["ok"], fg=C["success"])
        else:
            entry.config(highlightbackground=C["error"]); mark.config(text=ICON["err"], fg=C["error"])

    def _share_done(self, i):
        """Return on the last word / entry of share i: move to the next share,
        or submit when this was the last one."""
        if self._busy: return
        k = self._meta.get("threshold", 2) if self._meta else 2
        if self._imode.get() == "mnemonic":
            complete = sum(1 for inp in self._inputs if inp.is_complete())
            if complete >= k:
                self._start(); return
            for j, inp in enumerate(self._inputs):
                if j != i and not inp.is_complete():
                    inp.focus(); return
        else:
            filled = sum(1 for e in self._entries if e.get().strip().startswith("QCSHARE-"))
            if filled >= k:
                self._start(); return
            for j, e in enumerate(self._entries):
                if j != i and not e.get().strip():
                    e.focus_set(); return

    def _update_share_counter(self):
        """'N of k shares complete' — both input modes."""
        if not hasattr(self, "_share_counter"): return
        try:
            if not self._share_counter.winfo_exists(): return
        except Exception: return
        k = self._meta.get("threshold", 2) if self._meta else 2
        if self._imode.get() == "mnemonic":
            done = sum(1 for inp in self._inputs if inp.is_complete())
        else:
            done = sum(1 for e in self._entries if e.get().strip().startswith("QCSHARE-"))
        col = C["success"] if done >= k else (C["warning"] if done > 0 else C["text3"])
        glyph = f"  {ICON['ok']}" if done >= k else ""
        self._share_counter.config(
            text=f"{min(done, k)} of {k} shares complete{glyph}", fg=col)

    def _fill_shares(self, codes):
        """Put QCSHARE- codes into the slots in order (both modes).  Adds
        slots up to the file's total when more codes than slots were found."""
        k = self._meta.get("threshold", 2)
        n = self._meta.get("total", k)
        while self._slot_count() < min(len(codes), n):
            self._add_share_slot(start_expanded=False)
        if self._imode.get() == "mnemonic":
            skipped = []
            for i, inp in enumerate(self._inputs):
                if i < len(codes):
                    try:
                        mn = cc.share_to_mnemonic({**cc.decode_share(codes[i]), "threshold": k})
                        inp.set_words(mn.split())
                        if i > 0: inp.collapse()
                    except Exception:
                        skipped.append(i + 1)
                        inp.clear()
                else:
                    inp.clear()
            if skipped:
                self._set_error(f"{_share_list(skipped)} couldn't be read; the code may be damaged.")
        else:
            for i, entry in enumerate(self._entries):
                entry.delete(0, "end")
                if i < len(codes):
                    entry.insert(0, codes[i])
                self._mark_entry(entry)
        self._update_share_counter()

    def _paste_single_share(self, entry):
        """Paste a single QCSHARE- code from the clipboard into one entry."""
        try:
            text = self.clipboard_get().strip()
        except Exception:
            alert(self, "Nothing to paste", "The clipboard is empty.")
            return
        # If clipboard has multiple lines, grab the first QCSHARE- line
        code = text
        for ln in text.splitlines():
            ln = ln.strip()
            if ln.startswith("QCSHARE-"):
                code = ln
                break
        entry.delete(0, "end")
        entry.insert(0, code)
        self._mark_entry(entry)
        self._update_share_counter()

    def _paste_all_shares(self):
        """Find every share in the clipboard and fill the slots in order."""
        try:
            text = self.clipboard_get()
        except Exception:
            alert(self, "Nothing to paste", "The clipboard is empty."); return
        self._apply_found_shares(_extract_share_codes(text), "the clipboard")

    def _load_shares_from_files(self):
        """Open the .share-N-of-M.txt files the encryptor wrote (or any text
        file containing QCSHARE- codes / 50-word phrases) and fill the slots."""
        if self._busy: return
        paths = filedialog.askopenfilenames(
            parent=self, title="Choose share files",
            filetypes=[("Share files", "*.txt"), ("All files", "*")],
            initialdir=os.path.dirname(self._qcx_path) if self._qcx_path else os.path.expanduser("~"))
        if not paths: return
        codes, unreadable = [], []
        for p in paths:
            try:
                if os.path.getsize(p) > _MAX_SHARE_FILE:
                    unreadable.append(os.path.basename(p)); continue
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                unreadable.append(os.path.basename(p)); continue
            for c in _extract_share_codes(text):
                if c not in codes: codes.append(c)
        if unreadable:
            self._set_error(f"Couldn't read {', '.join(unreadable)}.")
        where = "that file" if len(paths) == 1 else "those files"
        self._apply_found_shares(codes, where)

    def _apply_found_shares(self, codes, where):
        if not codes:
            alert(self, "No shares found",
                  f"No QCSHARE- codes or 50-word phrases were found in {where}.")
            return
        k = self._meta.get("threshold", 2)
        if len(codes) < k:
            if not confirm(self, "Not enough shares",
                           f"Found {len(codes)} share{'s' if len(codes) != 1 else ''} in {where}, "
                           f"but this file needs {k}.\nFill the first {len(codes)} anyway?",
                           yes="Fill anyway", no="Cancel"):
                return
        self._fill_shares(codes)
        self._set_status(f"Loaded {min(len(codes), self._slot_count())} share"
                         f"{'s' if len(codes) != 1 else ''} from {where}.")

    def _rebuild_inputs(self):
        # The revert below writes _imode, which fires this trace again: the
        # guard has to come before the dialog, or "Keep editing" asks twice
        # (run 18 F-207).
        if getattr(self, "_rebuilding", False): return
        if self._meta and self._mode_val == "shamir":
            has_data = (
                any(inp.has_input() for inp in self._inputs)
                or any(e.get().strip() for e in self._entries)
            )
            if has_data:
                if not confirm(self, "Switch share format?",
                               "Switching the format clears every share you've entered so far.",
                               yes="Switch and clear", no="Keep editing", danger=True):
                    # Use try/finally so flag always gets reset, even on exception
                    try:
                        self._rebuilding = True
                        prev = "raw" if self._imode.get() == "mnemonic" else "mnemonic"
                        self._imode.set(prev)
                    finally:
                        self._rebuilding = False
                    return
            self._build_share_inputs(self._meta["threshold"])

    def _browse_out(self):
        cur = self._out.get().strip()
        if cur and os.path.isdir(cur):
            init_dir = cur
        elif cur:
            init_dir = os.path.dirname(os.path.abspath(cur))
        else:
            init_dir = os.path.expanduser("~")
        p = filedialog.askdirectory(initialdir=init_dir)
        if p:
            self._out.delete(0,"end"); self._out.insert(0, p)

    # ── Decrypt flow ──────────────────────────────────────────────────────────

    def _validate(self):
        if not self._payload: return "Open a .qcx file first"
        out_dir = self._out.get().strip()
        if not out_dir: return "Choose a folder to save the decrypted file in"
        if not os.path.isdir(out_dir): return "That output folder doesn't exist. Choose another"
        if self._mode_val == "single":
            if not hasattr(self, "_pw") or not self._pw.get(): return "Enter your password"
        else:
            # Need k usable shares; spare slots that were left empty are ignored
            k = self._meta.get("threshold", 2) if self._meta else 2
            if self._imode.get() == "mnemonic":
                complete = [inp for inp in self._inputs if inp.is_complete()]
                partial = [(i+1, inp.valid_count()) for i, inp in enumerate(self._inputs)
                           if inp.has_input() and not inp.is_complete()]
                if partial:
                    return "Incomplete: " + ", ".join(f"Share {i}: {n}/50 words" for i, n in partial)
                if len(complete) < k:
                    empty = [i+1 for i, inp in enumerate(self._inputs) if not inp.has_input()]
                    return (f"{_share_list(empty)} {'is' if len(empty)==1 else 'are'} empty; "
                            f"this file needs {k} shares")
            else:
                vals = [e.get().strip() for e in self._entries]
                bad_fmt = [i+1 for i, v in enumerate(vals) if v and not v.startswith("QCSHARE-")]
                if bad_fmt:
                    verb = "don't" if len(bad_fmt) > 1 else "doesn't"
                    return (f"{_share_list(bad_fmt)} {verb} look right: "
                            f"code shares start with QCSHARE-")
                good = [v for v in vals if v]
                if len(good) < k:
                    empty = [i+1 for i, v in enumerate(vals) if not v]
                    return (f"{_share_list(empty)} {'is' if len(empty)==1 else 'are'} empty; "
                            f"this file needs {k} shares")
        return None

    def _focus_first_bad(self):
        """Put the cursor on whatever the validation error is about, expanding
        a collapsed share panel if needed, so the message points at something visible."""
        try:
            if self._mode_val == "single":
                if hasattr(self, "_pw"): self._pw.focus_set()
                return
            if not self._out.get().strip() or not os.path.isdir(self._out.get().strip()):
                self._out.focus_set(); return
            if self._imode.get() == "mnemonic":
                for inp in self._inputs:
                    if inp.has_input() and not inp.is_complete():
                        inp.focus(); return
                for inp in self._inputs:
                    if not inp.has_input():
                        inp.focus(); return
            else:
                for e in self._entries:
                    v = e.get().strip()
                    if v and not v.startswith("QCSHARE-"):
                        e.focus_set(); return
                for e in self._entries:
                    if not e.get().strip():
                        e.focus_set(); return
        except Exception:
            pass

    def _shares_wrong_copy(self):
        k = self._meta.get("threshold", "?") if self._meta else "?"
        n = self._meta.get("total", "?") if self._meta else "?"
        return (f"These shares don't unlock this file. Any {k} of the {n} shares will "
                f"work, so try swapping in a different share. QuantaCrypt can't tell "
                f"which one is wrong.")

    def _focus_credential(self):
        """After a failure: back to the first credential input in either mode."""
        try:
            if self._mode_val == "single" and hasattr(self, "_pw"):
                self._pw.focus_set(); self._pw.selection_range(0, "end")
            elif self._inputs:
                self._inputs[0].focus()
            elif self._entries:
                self._entries[0].focus_set(); self._entries[0].selection_range(0, "end")
        except Exception:
            pass

    def _begin(self, verify, err):
        """Shared tail for Decrypt and Verify: show the validation result,
        capture widget state on the main thread, freeze the form, start the worker."""
        if self._busy: return
        if err:
            self._set_error(err)
            self._focus_first_bad()
            self.after(50, lambda: self._cv.yview_moveto(1.0))  # Scroll after layout reflow
            return
        out = self._out.get().strip()
        # Capture ALL Tk widget state on the main thread — widget reads are not thread-safe
        pw_captured = self._pw.get() if self._mode_val == "single" and hasattr(self, "_pw") else None
        shares_captured = None
        if self._mode_val != "single":
            try:
                shares_captured = self._collect_shares()
            except Exception as ex:
                if "Checksum" in str(ex):
                    self._set_error(self._shares_wrong_copy())
                else:
                    self._set_error(friendly_error(ex))
                self._focus_credential()
                self.after(50, lambda: self._cv.yview_moveto(1.0))
                return
        self._set_status(""); self._busy = True; self._verifying = verify
        self._extracting = False; self._cancel = False; self._finished_ok = False
        self._new_prog(_stages_for(self._mode_val, verify=verify))
        self._cancel_row.pack(fill="x", padx=P, pady=(0, SP["s"]), before=self._results)
        self._cancel_btn.enable(True)
        self._prog.start(); self._freeze(); self._wiz.set_step(2)
        self.after(50, lambda: self._cv.yview_moveto(1.0))
        self.after(60, self._cancel_btn.focus_set)
        for w in self._results.winfo_children(): w.destroy()
        if verify:
            threading.Thread(target=self._verify_run,
                             args=(pw_captured, shares_captured), daemon=True).start()
        else:
            threading.Thread(target=self._run,
                             args=(out, pw_captured, shares_captured), daemon=True).start()

    def _start(self):
        if self._busy: return
        self._begin(verify=False, err=self._validate())

    def _freeze(self):
        """Disable every interactive control while decryption runs — including
        the share inputs and their Paste / Clear / Load buttons."""
        self._btn.enable(False)
        self._verify_btn.enable(False)
        try: self._browse_btn.enable(False)  # Prevent browse during decrypt
        except Exception: pass
        try: self._out.config(state="disabled")
        except Exception: pass
        try: self._file_card.set_enabled(False)
        except Exception: pass
        try:
            if self._mode_val == "single" and hasattr(self, "_pw"):
                self._pw.config(state="disabled")
                self._eye_btn.enable(False)
        except Exception: pass
        for inp in self._inputs:
            try: inp.set_enabled(False)
            except Exception: pass
        for e in self._entries:
            try: e.config(state="disabled")
            except Exception: pass
        for b in self._share_btns:
            try: b.enable(False)
            except Exception: pass

    def _thaw(self):
        """Re-enable all interactive controls after decryption completes or fails."""
        self._btn.enable(True)
        if self._payload: self._verify_btn.enable(True)
        try: self._browse_btn.enable(True)  # Restore browse button
        except Exception: pass
        try: self._out.config(state="normal")
        except Exception: pass
        try: self._file_card.set_enabled(True)
        except Exception: pass
        try:
            if self._mode_val == "single" and hasattr(self, "_pw"):
                self._pw.config(state="normal")
                if hasattr(self, "_eye_btn"): self._eye_btn.enable(True)
        except Exception: pass
        for inp in self._inputs:
            try: inp.set_enabled(True)
            except Exception: pass
        for e in self._entries:
            try: e.config(state="normal")
            except Exception: pass
        for b in self._share_btns:
            try: b.enable(True)
            except Exception: pass
        self._refresh_add_btn()

    def _new_prog(self, stages):
        """Replace the progress bar with one whose dots match ``stages``
        and pack it into the progress slot above the results."""
        old = getattr(self, "_prog", None)
        if old is not None:
            try: old.stop(); old.destroy()
            except Exception: pass
        self._run_stages = list(stages)
        self._prog = StagedProgressBar(self._body, [(n, w) for n, w, _ in stages])
        self._prog.pack(fill="x", padx=P, pady=(0, SP["xs"]), before=self._results)
        return self._prog

    def _prog_cb(self, msg):
        # Friendly stage name + percentage only; the raw core string never reaches the bar
        idx, label = _find_stage(msg, self._run_stages)
        if idx is not None:
            self._after(lambda: self._prog.advance(idx, label) if self._busy else None)

    def _run(self, out_dir, pw_captured, shares_captured=None):
        """Worker thread.  The whole pipeline — key derivation, HMAC check,
        0600 mkstemp output, never-overwrite naming — is core.package's
        decrypt_qcx, shared with qc-core so the two can't drift."""
        try:
            res = pkg.decrypt_qcx(
                self._qcx_path, out_dir,
                password=pw_captured, shares=shares_captured,
                progress=self._prog_cb, cancel_check=lambda: self._cancel)
            pw_captured = None  # noqa: F841 — release str reference
            if self._mode_val == "single":
                self._after(self._clear_pw)
            self._after(lambda: self._done(
                res["output"], res["size"], res["filename"],
                res["original_size"], res["timestamp"], res["renamed"]))
        except cc.CancelledOperation:
            self._after(self._cancelled)
        except Exception as ex:
            self._after(lambda exc=ex: self._fail(exc))

    def _clear_pw(self):
        """Clear the password entry on the main thread after a successful
        decryption.  It is still frozen (disabled) at this point and a
        disabled Entry silently ignores delete(), so lift the state first."""
        if hasattr(self, "_pw"):
            try:
                prev = str(self._pw.cget("state"))
                self._pw.config(state="normal")
                self._pw.delete(0, "end")
                self._pw.config(state=prev)
            except Exception: pass

    def _collect_shares(self):
        """Gather the filled shares (main thread), reject duplicates, and
        return the first k as QCSHARE- codes."""
        k = self._meta.get("threshold", 0)
        slots = []   # (slot number, share dict, code)
        if self._imode.get() == "mnemonic":
            for i, inp in enumerate(self._inputs, 1):
                if not inp.is_complete(): continue
                sd = cc.mnemonic_to_share(inp.get_mnemonic())
                mn_k = sd.get("threshold", 0)
                if mn_k and mn_k != k:
                    raise ValueError(
                        f"Share {i} doesn't match this file. It was created for a "
                        f"different encryption that needs {mn_k} people, but this file "
                        f"needs {k}. Check you have the right shares."
                    )
                slots.append((i, sd, cc.encode_share(sd)))
        else:
            for i, e in enumerate(self._entries, 1):
                code = e.get().strip()
                if not code: continue
                try:
                    sd = cc.decode_share(code)
                except (ValueError, TypeError) as ex:
                    raise ValueError(
                        f"Share {i} can't be read: the code may be incomplete or damaged. "
                        f"Paste the whole QCSHARE- line again."
                    ) from ex
                slots.append((i, sd, code))
        # The same share pasted twice recovers nothing, and the failure would
        # otherwise surface as a cryptic wrong-key error.
        seen = {}
        for i, sd, _ in slots:
            key = (sd.get("index"), sd.get("value"))
            if key in seen:
                raise ValueError(
                    f"Shares {seen[key]} and {i} are the same share. You need {k} different shares."
                )
            seen[key] = i
        return [code for _, _, code in slots[:k]]

    def _start_verify(self):
        """Validate the password/shares decrypt the file without writing any output.
        Derives keys, verifies the metadata HMAC, and decrypts the first chunk only.
        Gives confidence the credentials are correct before doing a full decrypt."""
        if self._busy: return
        self._begin(verify=True, err=self._validate())

    def _verify_run(self, pw_captured, shares_captured=None):
        """Worker thread: derive + HMAC-check the key (core.package
        derive_final_key), then decrypt chunk 0 only (verify_first_chunk).
        No output is written."""
        try:
            final_key, _hmac_key = pkg.derive_final_key(
                self._meta, password=pw_captured, shares=shares_captured,
                progress=self._prog_cb, cancel_check=lambda: self._cancel)
            pw_captured = None  # noqa: F841 — release str reference
            if self._cancel:
                raise cc.CancelledOperation()
            self._prog_cb("Checking file integrity...")
            pkg.verify_first_chunk(self._qcx_path, self._meta, final_key)
            self._after(self._verify_done)
        except cc.CancelledOperation:
            self._after(self._cancelled)
        except Exception as ex:
            self._after(lambda exc=ex: self._fail(exc))

    def _verify_done(self):
        """Show verification success without writing any output."""
        self._busy = False; self._prog.complete(); self._cancel_row.pack_forget(); self._thaw()
        self._pw_failures = 0
        # Nothing was written — the Decrypt step is not done, so stay on it
        self._wiz.set_step(2)
        ok = card(self._results, padx=SP["l"], pady=SP["m"])
        ok.outer.config(highlightbackground=C["success"])
        ok.outer.pack(fill="x", pady=(SP["l"],0))
        tk.Label(ok, text=f"{ICON['ok']}  Key verified. Your credentials are correct",
                 font=F["body_b"], bg=C["surface"], fg=C["success"]).pack(anchor="w")
        tk.Label(ok, text="Your password / shares decrypted the first block. "
                          "Nothing has been written to disk yet.",
                 font=F["caption"], bg=C["surface"], fg=C["text3"],
                 anchor="w", justify="left", wraplength=490).pack(anchor="w", pady=(SP["xs"],SP["s"]))
        btn_row = tk.Frame(ok, bg=C["surface"]); btn_row.pack(fill="x")
        go = FlatButton(btn_row, f"Decrypt now {ICON['arrow']}", self._reset_and_decrypt,
                        primary=True, small=True)
        go.pack(side="left")
        FlatButton(btn_row, f"Decrypt another {ICON['arrow']}", self._reset,
                   primary=False, small=True).pack(side="left", padx=(SP["s"],0))
        self.after(50, lambda: self._cv.yview_moveto(1.0))
        self.after(60, lambda: go.focus_set() if go.winfo_exists() else None)

    def _reset_and_decrypt(self):
        """After a successful verify, decrypt with the credentials still in the
        form — no reset, no re-entering the password or shares."""
        for w in self._results.winfo_children(): w.destroy()
        self._start()

    def _done(self, path, size, fname="", sz=0, ts=0, renamed=False):
        self._busy=False; self._finished_ok=True
        self._prog.complete(); self._cancel_row.pack_forget(); self._thaw()
        # Immediately disable the Decrypt button — _thaw() re-enables it,
        # but on success it must stay disabled until "Decrypt another" is clicked.
        # Doing this before building the card avoids a visible flash of the enabled state.
        self._btn.enable(False)
        self._pw_failures = 0
        # set_step past the last step → all circles show ✓ (complete)
        self._wiz.set_step(len(self.STEPS))
        display = os.path.basename(fname) if fname else os.path.basename(path)
        notify("Decryption complete", display)
        # Store sz/ts and recovered filename so FileInfoCard shows them
        self._sz = sz; self._ts = ts
        # Update _orig with the decrypted filename and refresh the info card
        self._orig = os.path.basename(fname) if fname else None
        # Add to recent files list
        try:
            RecentFiles.add(self._qcx_path, self._meta)
        except Exception:
            pass
        for w in self._info_wrap.winfo_children(): w.destroy()
        if self._meta:
            FileInfoCard(self._info_wrap, self._meta, self._orig,
                         sz=sz, ts=ts).pack(fill="x")
        # Clear all share inputs from UI after successful decryption (security)
        cleared_shares = False
        for inp in self._inputs:
            try: inp.clear(); cleared_shares = True
            except Exception: pass
        # Also clear raw QCSHARE- entry widgets (used in raw mode)
        for entry in getattr(self, "_entries", []):
            try:
                entry.config(state="normal")
                entry.delete(0, "end")
                self._mark_entry(entry)
            except Exception: pass
        if self._entries: cleared_shares = True
        self._update_share_counter()

        ok = card(self._results, padx=SP["l"], pady=SP["m"])
        ok.outer.config(highlightbackground=C["success"])
        ok.outer.pack(fill="x", pady=(SP["l"],0))
        ok_in = tk.Frame(ok, bg=C["surface"]); ok_in.pack(fill="x")
        tk.Label(ok_in, text=f"{ICON['ok']}  Decrypted successfully", font=F["body_b"],
                 bg=C["surface"], fg=C["success"]).pack(side="left")
        tk.Label(ok_in, text=fmt_size(size), font=F["caption"],
                 bg=C["surface"], fg=C["text3"]).pack(side="right")
        # Sanitize: apply basename so metadata-embedded paths can't mislead user
        display_name = (os.path.basename(fname) if fname else None) or os.path.basename(path)
        # Only show separate filename line when it differs from the output path basename
        if display_name != os.path.basename(path):
            tk.Label(ok, text=display_name, font=F["mono"],
                     bg=C["surface"], fg=C["text2"]).pack(anchor="w", pady=(SP["xs"],0))
        # Show full output path so user knows exactly where it went
        tk.Label(ok, text=path, font=F["caption"],
                 bg=C["surface"], fg=C["text3"], anchor="w",
                 wraplength=490, justify="left").pack(anchor="w", pady=(SP["xs"],0))
        if renamed:
            tk.Label(ok, text=(f"A file named {display_name} already existed there, "
                               f"so this one was saved as {os.path.basename(path)}."),
                     font=F["caption"], bg=C["surface"], fg=C["warning"], anchor="w",
                     wraplength=490, justify="left").pack(anchor="w", pady=(SP["xs"],0))
        # Show original size and timestamp if available
        if sz or ts:
            info_parts = []
            if sz: info_parts.append(f"Original: {fmt_size(sz)}")
            if ts:
                try: info_parts.append(f"Encrypted: {_time.strftime('%Y-%m-%d %H:%M', _time.localtime(ts))}")
                except Exception: pass
            if info_parts:
                tk.Label(ok, text="  ·  ".join(info_parts), font=F["caption"],
                         bg=C["surface"], fg=C["text3"]).pack(anchor="w", pady=(SP["xs"],0))
        # Note that shares were cleared for security
        if cleared_shares:
            tk.Label(ok, text="Share inputs were cleared after decryption.",
                     font=F["caption"], bg=C["surface"], fg=C["text3"]).pack(anchor="w", pady=(SP["xs"],0))
        # Label the button so it's clear re-running needs "Decrypt another →"
        self._btn.config(text=f"Decrypt again {ICON['arrow']}")
        # Reveal + decrypt another
        btn_row = tk.Frame(ok, bg=C["surface"]); btn_row.pack(fill="x", pady=(SP["s"],0))
        another = FlatButton(btn_row, f"Decrypt another {ICON['arrow']}", self._reset,
                             primary=False, small=True)
        another.pack(side="left")
        # If output looks like a folder-encrypted zip, offer one-click extraction
        _is_folder_zip = (fname or "").endswith(".zip") and os.path.isfile(path) and zipfile.is_zipfile(path)
        if _is_folder_zip:
            FlatButton(btn_row, "Extract folder", lambda p=path: self._extract_folder(p),
                       primary=True, small=True).pack(side="left", padx=(SP["s"],0))
        else:
            FlatButton(btn_row, "Open file", lambda: _open_file(path), primary=False, small=True).pack(side="left", padx=(SP["s"],0))
        FlatButton(btn_row, REVEAL_LABEL, lambda: self._reveal(path), primary=False, small=True).pack(side="left", padx=(SP["s"],0))
        self.after(50, lambda: self._cv.yview_moveto(1.0))
        self.after(60, lambda: another.focus_set() if another.winfo_exists() else None)

    # ── Extract folder ────────────────────────────────────────────────────────

    def _extract_folder(self, zpath):
        """Unpack the decrypted folder archive next to it, into a directory
        that does not exist yet (never over an existing one), on a worker
        thread with the progress bar and Cancel.  Entries that could escape
        the destination are rejected up front; oversized archives are
        confirmed first."""
        if self._busy: return
        out_dir = os.path.dirname(os.path.abspath(zpath))
        try:
            with zipfile.ZipFile(zpath) as zf:
                infos = zf.infolist()
        except Exception as ex:
            alert(self, "Extraction failed", friendly_error(ex)); return
        bad = [i.filename for i in infos if not _zip_member_ok(i.filename)]
        if bad:
            alert(self, "Archive not extracted",
                  f"The archive contains an unsafe path ({bad[0]!r}) that could write "
                  "outside the destination folder, so nothing was extracted.")
            return
        total = sum(i.file_size for i in infos)
        if len(infos) > _EXTRACT_MAX_ENTRIES or total > _EXTRACT_MAX_BYTES:
            if not confirm(self, "Large archive",
                           f"This archive expands to {fmt_size(total)} in {len(infos):,} entries. "
                           "Extract it anyway?", yes="Extract", no="Cancel"):
                return
        names = [i.filename.replace("\\", "/") for i in infos]
        roots = {n.split("/")[0] for n in names}
        single_root = roots.pop() if len(roots) == 1 else None
        # Only a directory can be stripped.  A lone top-level file has the
        # same one-root shape, but it must land inside the new folder, not
        # become an empty folder of its own name.
        if single_root and any(n.rstrip("/") == single_root and not i.is_dir()
                               for n, i in zip(names, infos)):
            single_root = None
        top = single_root or os.path.splitext(os.path.basename(zpath))[0] or "extracted"
        dest, renamed = pkg.unique_path(out_dir, top)

        self._set_status("")
        self._busy = True; self._extracting = True; self._verifying = False
        self._cancel = False; self._finished_ok = False
        self._new_prog(STAGE_EXTRACT)
        self._cancel_row.pack(fill="x", padx=P, pady=(0, SP["s"]), before=self._results)
        self._cancel_btn.enable(True)
        self._prog.start(); self._freeze()
        self.after(50, lambda: self._cv.yview_moveto(1.0))
        threading.Thread(target=self._extract_run,
                         args=(zpath, dest, single_root, total, renamed), daemon=True).start()

    def _extract_run(self, zpath, dest, strip_root, declared, renamed):
        """Worker: stream every member into ``dest`` (created fresh here).
        Bytes written are bounded by the archive's own index so a mismatch
        aborts instead of filling the disk; a cancel or failure removes
        the half-written directory."""
        written = 0
        created = False   # only a directory THIS run made is ever removed
        try:
            try:
                # 0700 / 0600 throughout: the archive came out of a 0600
                # plaintext, and the process umask must not widen it.
                os.makedirs(dest, mode=0o700)
            except FileExistsError:
                raise RuntimeError(
                    f"A folder named {os.path.basename(dest)} appeared in "
                    f"{os.path.dirname(dest)} just before extraction started. "
                    "nothing was extracted.") from None
            created = True
            # Extracted content is as foreign as the .qcx it came from; the
            # stamp is what makes Gatekeeper look at an .app inside it.
            pkg._mark_quarantined(dest)
            real_dest = os.path.realpath(dest)
            with zipfile.ZipFile(zpath) as zf:
                infos = zf.infolist()
                n = len(infos) or 1
                for i, info in enumerate(infos, 1):
                    if self._cancel:
                        raise cc.CancelledOperation()
                    rel = info.filename.replace("\\", "/")
                    parts = [p for p in rel.split("/") if p]
                    # A whole component, never a string prefix: "docs-old/x"
                    # must not lose "docs" and turn into "-old/x".
                    if strip_root and parts and parts[0] == strip_root:
                        parts = parts[1:]
                    target = os.path.join(dest, *parts) if parts else dest
                    if os.path.commonpath([real_dest, os.path.realpath(target)]) != real_dest:
                        raise ValueError(f"Archive entry escapes the destination: {info.filename}")
                    if info.is_dir() or not parts:
                        _makedirs_private(target)
                        continue
                    _makedirs_private(os.path.dirname(target))
                    # O_EXCL: the tree is this run's own, so an existing name
                    # can only be a duplicate entry — refused, not overwritten.
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with zf.open(info) as src, os.fdopen(fd, "wb") as dst:
                        while True:
                            chunk = src.read(1 << 20)
                            if not chunk: break
                            written += len(chunk)
                            if written > declared + (1 << 20):
                                raise ValueError("Archive contents don't match its index. Extraction stopped.")
                            dst.write(chunk)
                            if self._cancel:
                                raise cc.CancelledOperation()
                    pkg._mark_quarantined(target)
                    self._prog_cb(f"Extracting folder... {int(i / n * 100)}%")
            self._after(lambda: self._extract_done(dest, renamed))
        except cc.CancelledOperation:
            if created:
                shutil.rmtree(dest, ignore_errors=True)
            self._after(self._cancelled)
        except Exception as ex:
            if created:
                shutil.rmtree(dest, ignore_errors=True)
            self._after(lambda exc=ex: self._extract_failed(exc))

    def _extract_end(self, ok):
        """Back to the post-decrypt result state (Decrypt stays disabled
        until "Decrypt another", as _done left it)."""
        self._busy = False; self._extracting = False; self._cancel = False
        if ok: self._prog.complete()
        else:  self._prog.stop(); self._prog.pack_forget()
        self._cancel_row.pack_forget()
        self._thaw()
        self._btn.enable(False)

    def _extract_done(self, dest, renamed):
        self._extract_end(ok=True)
        self._finished_ok = True
        name = os.path.basename(dest)
        note = (f"\n\nA folder named {os.path.basename(os.path.dirname(dest))}/"
                f"{name.rsplit('_', 1)[0]} already existed, so it was extracted as {name}."
                if renamed else "")
        self._set_status(f"{ICON['ok']} Folder extracted to {dest}")
        self._reveal(dest)
        alert(self, "Folder extracted", f"The folder was extracted to:\n{dest}{note}")

    def _extract_failed(self, exc):
        self._extract_end(ok=False)
        self._set_error("Extraction failed. Nothing was kept.", friendly_error(exc))
        alert(self, "Extraction failed", friendly_error(exc))

    def _reveal(self, path):
        if not reveal_path(path):
            self._set_status(f"Couldn't open the file manager. The file is at {path}")

    def _reset(self):
        self._payload  = None; self._meta = None; self._orig = None
        self._mode_val = None; self._inputs = []; self._entries = []
        self._entry_marks = []; self._share_btns = []; self._add_btn = None
        self._sz = 0; self._ts = 0; self._pw_failures = 0
        # Clear trace ID so next file load does not attempt to remove a stale ID
        if self._imode_trace_id:
            try: self._imode.trace_remove("write", self._imode_trace_id)
            except Exception: pass
            self._imode_trace_id = None
        self._out.delete(0, "end")
        self._out_hint.config(text=OUT_HINT_EMPTY)
        self._set_status("")
        for w in self._results.winfo_children(): w.destroy()
        for w in self._info_wrap.winfo_children(): w.destroy()
        for w in self._inspect_row.winfo_children(): w.destroy()
        for w in self._sec_wrap.winfo_children(): w.destroy()
        self._verify_btn.enable(False)
        self._sec_label.config(text="2  PASSWORD")
        tk.Label(self._sec_wrap, text=SEC_HINT_EMPTY,
                 font=F["caption"], bg=C["bg"], fg=C["text3"]).pack(anchor="w")
        # Same prompt as the initial build; the drop hint follows what was registered
        self._file_card.reset(FILE_PROMPT)
        # btn stays disabled — re-enabled by _load_payload when a valid file is opened
        self._btn.config(text="Open a file to begin")  # Neutral text while disabled
        self._prog.pack_forget(); self._wiz.set_step(0)
        self.title("QuantaCrypt · Decrypt")
        self.after(10, lambda: self._cv.yview_moveto(0))
        self.after(20, self._file_card.focus_set)  # Restore focus after reset

    def _request_cancel(self):
        """User hit Cancel — flag the worker; it raises CancelledOperation
        at the next chunk boundary."""
        if not self._busy:
            return
        self._cancel = True
        try:
            self._cancel_btn.enable(False)
        except Exception:
            pass
        self._set_status("Cancelling. Finishing the current step…")

    def _cancelled(self):
        """Post-cancel UI reset."""
        if self._extracting:
            self._extract_end(ok=False)
            self._set_status("Extraction cancelled. Nothing was kept.")
            return
        self._busy = False
        self._cancel = False
        self._prog.stop()
        self._prog.pack_forget()
        self._cancel_row.pack_forget()
        self._thaw()
        self._wiz.set_step(2)
        what = "Verification" if self._verifying else "Decryption"
        self._set_status(f"{what} cancelled. Nothing was written.")
        notify(f"{what} cancelled", "Nothing was written.", sound=False)
        self._focus_credential()

    def _fail(self, exc):
        """Worker failure → one plain sentence on the status line.  Only the
        two credential cases get bespoke copy; everything else goes through
        friendly_error() so the two wizards can't drift apart again.

        The credential cases are decided by core.errors.classify_error, not
        by the exception's type name: a payload that fails authentication
        AFTER derive_final_key proved the key (CorruptPayload, code
        ``format``) is a damaged copy and must never be called a wrong
        password — that advice sends the user to re-type a correct one."""
        self._busy=False; self._cancel=False
        self._prog.stop(); self._prog.pack_forget(); self._cancel_row.pack_forget(); self._thaw()
        self._wiz.set_step(2)  # stay at Decrypt step — error is shown there
        if not isinstance(exc, BaseException):   # tolerate a pre-mapped string
            exc = RuntimeError(str(exc))
        msg = str(exc) or type(exc).__name__
        code, _message, _detail = classify_error(exc)
        wrong_key = code == "wrong_credentials"
        detail = ""
        if isinstance(exc, CorruptPayload):
            text = friendly_error(exc)   # the key was right; this copy is damaged
        elif wrong_key and self._mode_val == "single":
            self._pw_failures += 1
            text = ("Wrong password. Check Caps Lock, use Show to see what you typed, "
                    "and try again.")
            if self._pw_failures >= 3:
                detail = NO_RECOVERY_NOTE
        elif wrong_key or "Checksum" in msg or "out of range" in msg.lower():
            text = self._shares_wrong_copy()
        else:
            text = friendly_error(exc)   # format / io / invalid_input: the helper's own sentence
        self._set_error(text, detail)
        notify("Decryption failed", text, sound=False)
        # Defer focus so _thaw's state=normal is processed first
        self.after(10, self._focus_credential)
        # Scroll to bottom so the error label is visible
        self.after(50, lambda: self._cv.yview_moveto(1.0))  # Reflow delay


def main():
    payload = qcx_path = None
    if getattr(sys,"frozen",False):
        try: payload = load_pkg(sys.executable); qcx_path = sys.executable
        except ValueError: pass
    DecryptorApp(payload=payload, qcx_path=qcx_path).mainloop()

if __name__ == "__main__":
    main()
