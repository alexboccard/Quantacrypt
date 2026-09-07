"""QuantaCrypt Shared UI Design System."""

import os
import queue
import sys
import threading
import time

import tkinter as tk

__all__ = [
    "C", "F", "UI", "MONO", "SP", "ICON", "MOD", "MOD_LABEL", "REVEAL_LABEL",
    "accel", "bind_shortcut", "safe_after", "write_new_private_file",
    "styled_entry", "bind_context_menu", "fmt_size", "rule", "section_label",
    "card", "kv_row", "confirm", "alert", "reveal_path", "copy_secret",
    "FlatButton", "SegmentedControl", "StagedProgressBar",
    "PasswordStrengthBar", "FileCard", "WizardSteps",
    "ClipboardTimer", "RecentFiles", "RecentVolumes", "AppPrefs",
]

# ── Colors ────────────────────────────────────────────────────────────────────
# Every pair below was contrast-checked (WCAG): text on accent 4.7:1, text on
# accent_hover 6.2:1, text on error_fill 5.2:1, text3 on surface 5.0:1,
# accent_text on surface 5.5:1.  "accent" is a FILL colour (buttons, selected
# segments, progress); use "accent_text" for links and emphasis on dark
# surfaces — the fill is too dark to read as text.
C = {
    "bg":           "#1c1c1e",
    "surface":      "#2c2c2e",
    "surface2":     "#3a3a3c",
    "surface3":     "#48484a",
    "border":       "#48484a",
    "accent":       "#2f6fb8",   # fill
    "accent_hover": "#265d9c",   # hover goes darker so contrast rises
    "accent_press": "#1f4c80",
    "accent_dim":   "#2d5a8a",
    "accent_text":  "#6aa6e8",   # links / active labels on dark surfaces
    "text":         "#f5f5f7",
    "text2":        "#c8c8cc",
    "text3":        "#9a9aa0",
    "success":      "#30d158",
    "error":        "#ff453a",   # error TEXT on bg
    "error_fill":   "#c22d26",   # danger button fill
    "error_hover":  "#a8241e",
    "warning":      "#ffd60a",
    "warn_dim":     "#7a6500",
}

# ── Fonts ─────────────────────────────────────────────────────────────────────
# Tk silently substitutes the system family when a font is missing, so a
# hard-coded "DejaVu Sans Mono" turns PROPORTIONAL on macOS (verified: both
# DejaVu faces resolve to .AppleSystemUIFont).  Pick per platform.
if sys.platform == "darwin":
    UI, MONO = ".AppleSystemUIFont", "Menlo"
elif sys.platform == "win32":
    UI, MONO = "Segoe UI", "Consolas"
else:
    UI, MONO = "DejaVu Sans", "DejaVu Sans Mono"

# Type scale: base 13 × 1.2ⁿ → 11 / 13 / 16 / 19 / 22 / 27.  "small" (10) is
# the one sub-scale size, reserved for meta text (dates, counters, hints).
F = {
    "hero":    (UI, 27, "bold"),
    "display": (UI, 22, "bold"),
    "title":   (UI, 19, "bold"),
    "heading": (UI, 16, "bold"),
    "body":    (UI, 13),
    "body_b":  (UI, 13, "bold"),
    "caption": (UI, 11),
    "caption_u": (UI, 11, "underline"),
    "small":   (UI, 10),
    "mono":    (MONO, 12),
    "mono_s":  (MONO, 10),
}

# Spacing scale (pt).  Every padx/pady should be one of these.
SP = {"xs": 4, "s": 8, "m": 12, "l": 16, "xl": 24, "xxl": 32}

# Status glyphs — the only non-letter symbols the UI draws.  Kept in one map
# so they can be swapped or suppressed per platform; never use colour emoji.
ICON = {"ok": "✓", "err": "✗", "warn": "⚠", "arrow": "→", "back": "←",
        "chevron_open": "▾", "chevron_closed": "▸", "close": "×"}

# Platform modifier for keyboard shortcuts.  ⌘ on macOS, Ctrl elsewhere.
MOD       = "Command" if sys.platform == "darwin" else "Control"
MOD_LABEL = "⌘" if sys.platform == "darwin" else "Ctrl+"
# One label for "show me this file in the file manager" on every screen.
REVEAL_LABEL = "Show in Finder" if sys.platform == "darwin" else "Show in folder"


def accel(key: str) -> str:
    """Human-readable accelerator: accel("O") → "⌘O" / "Ctrl+O"."""
    return f"{MOD_LABEL}{key}"


def bind_shortcut(widget, key: str, handler, *, also_control: bool = True):
    """Bind <Mod-key> (both cases) — the platform modifier, plus Ctrl on
    macOS when ``also_control`` so muscle-memory from other platforms still
    works.  ``key`` is a single letter or a Tk keysym like "Return"."""
    def _cb(_e, h=handler):
        h()
        return "break"
    keys = {key.lower(), key.upper()} if len(key) == 1 else {key}
    mods = {MOD}
    if also_control:
        mods.add("Control")
    for m in mods:
        for k in keys:
            widget.bind(f"<{m}-{k}>", _cb)


def safe_after(widget, fn, delay: int = 0) -> None:
    """Schedule ``fn`` on the Tk main thread from a worker thread.

    Every wizard hands worker results to the UI through ``after()``.  That is
    safe only with a threaded Tcl build (python.org, Homebrew and PyInstaller
    Tcl on macOS all are; some Linux distro builds are not) — with a
    non-threaded Tcl the call raises RuntimeError instead of corrupting the
    interpreter.  This helper swallows that, plus the TclError raised once the
    window is gone, so a worker can never crash on a hop the user has already
    walked away from.  ``fn`` itself is skipped when the widget was destroyed
    in the meantime."""
    def _safe():
        try:
            if widget.winfo_exists():
                fn()
        except tk.TclError:
            pass
    try:
        widget.after(delay, _safe)
    except (tk.TclError, RuntimeError):
        pass  # window destroyed / non-threaded Tcl / interpreter shutting down


_MAX_NAME_ATTEMPTS = 99   # <stem>_2 … <stem>_99, then give up (same cap as the native app)


def write_new_private_file(path: str, text: str) -> tuple[str, bool]:
    """Create ``path`` 0600 with O_EXCL — never over an existing file.  When
    the name is taken the file goes to the next free ``<stem>_N<ext>`` and
    ``renamed`` is True so the caller can say so.  Key material is written
    this way in every screen so a second run can't silently destroy the
    only copy of the first run's shares.

    The free-name probe uses ``lexists``: ``open(O_EXCL)`` fails on a
    dangling symlink too, and ``exists`` would keep proposing that same
    name forever.  After ``_MAX_NAME_ATTEMPTS`` names ``FileExistsError``
    is raised instead of looping."""
    import errno
    d = os.path.dirname(path) or "."
    root, ext = os.path.splitext(os.path.basename(path))
    for n in range(1, _MAX_NAME_ATTEMPTS + 1):
        out = path if n == 1 else os.path.join(d, f"{root}_{n}{ext}")
        if os.path.lexists(out):
            continue
        try:
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue   # appeared between the probe and the open — next name
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            # This file is the only copy of a share: it has to be on disk,
            # not in a page cache a power cut would discard.
            f.flush()
            os.fsync(f.fileno())
        return out, n > 1
    raise FileExistsError(
        errno.EEXIST,
        f"{_MAX_NAME_ATTEMPTS} files named like {os.path.basename(path)} already "
        "exist here. Choose another name or folder", path)


def bind_context_menu(widget):
    """Attach a right-click Cut / Copy / Paste / Select All menu to any
    Entry or Text widget.  Works on macOS (Button-2 or Control-Button-1)
    and Linux/Windows (Button-3)."""

    def _show(event):
        # One menu per widget, rebuilt per click: a new tk.Menu on every
        # right-click lived for the window's lifetime (run 18 F-208).
        menu = getattr(widget, "_ctx_menu", None)
        if menu is None or not menu.winfo_exists():
            menu = tk.Menu(widget, tearoff=0,
                           bg=C["surface2"], fg=C["text"],
                           activebackground=C["accent"], activeforeground=C["text"],
                           font=F["caption"], relief="flat", bd=0)
            widget._ctx_menu = menu
        else:
            menu.delete(0, "end")
        is_text = isinstance(widget, tk.Text)
        has_sel = False
        try:
            if is_text:
                has_sel = bool(widget.tag_ranges("sel"))
            else:
                has_sel = widget.selection_present()
        except Exception:
            pass

        # Cut  (only for editable widgets with a selection)
        read_only = str(widget.cget("state")) in ("disabled", "readonly")
        if has_sel and not read_only:
            menu.add_command(label="Cut", accelerator="⌘X",
                             command=lambda: widget.event_generate("<<Cut>>"))
        # Copy
        if has_sel:
            menu.add_command(label="Copy", accelerator="⌘C",
                             command=lambda: widget.event_generate("<<Copy>>"))
        # Paste
        if not read_only:
            menu.add_command(label="Paste", accelerator="⌘V",
                             command=lambda: widget.event_generate("<<Paste>>"))
        # Select All
        if is_text:
            menu.add_separator()
            menu.add_command(label="Select All", accelerator="⌘A",
                             command=lambda: (widget.tag_add("sel", "1.0", "end"),
                                              widget.mark_set("insert", "end")))
        else:
            content = widget.get()
            if content:
                menu.add_separator()
                menu.add_command(label="Select All", accelerator="⌘A",
                                 command=lambda: (widget.select_range(0, "end"),
                                                  widget.icursor("end")))

        if menu.index("end") is not None:
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

    # macOS uses Button-2 or Control-Button-1; Linux/Windows use Button-3
    widget.bind("<Button-2>", _show)
    widget.bind("<Control-Button-1>", _show)
    widget.bind("<Button-3>", _show)
    return widget


def styled_entry(parent, **kw):
    e = tk.Entry(
        parent, bg=C["surface2"], fg=C["text"],
        insertbackground=C["accent_text"], relief="flat",
        highlightbackground=C["border"], highlightcolor=C["accent_text"],
        highlightthickness=1, font=F["body"], **kw)
    bind_context_menu(e)
    return e


def card(parent, padx=SP["m"], pady=SP["s"], **kw):
    """The one card recipe: surface fill + hairline border.  Returns the
    inner frame to pack content into (so callers never retype the border)."""
    outer = tk.Frame(parent, bg=C["surface"],
                     highlightbackground=C["border"], highlightthickness=1, **kw)
    inner = tk.Frame(outer, bg=C["surface"])
    inner.pack(fill="both", expand=True, padx=padx, pady=pady)
    inner.outer = outer  # type: ignore[attr-defined]
    return inner


def kv_row(parent, label, value, *, label_width=11, wraplength=340, pady=3):
    """Label/value row used by every metadata card (file info, inspect, results)."""
    row = tk.Frame(parent, bg=parent.cget("bg"))
    row.pack(fill="x", pady=pady)
    tk.Label(row, text=label, font=F["caption"], bg=row.cget("bg"), fg=C["text3"],
             width=label_width, anchor="w").pack(side="left")
    val = tk.Label(row, text=value, font=F["caption"], bg=row.cget("bg"),
                   fg=C["text2"], anchor="w", wraplength=wraplength, justify="left")
    val.pack(side="left", fill="x")
    return val


def _dialog(parent, title, message, buttons, *, danger=False, default=0):
    """Themed modal dialog.  ``buttons`` is a list of (label, value); the
    first is the primary action.  Returns the chosen value (or the last
    button's value on Escape / window close)."""
    win = tk.Toplevel(parent)
    win.title(title)
    win.configure(bg=C["bg"])
    win.resizable(False, False)
    win.transient(parent)
    result = {"v": buttons[-1][1]}
    P = SP["xl"]
    tk.Label(win, text=title, font=F["heading"], bg=C["bg"], fg=C["text"],
             wraplength=380, justify="left").pack(anchor="w", padx=P, pady=(P - 4, SP["s"]))
    tk.Label(win, text=message, font=F["body"], bg=C["bg"], fg=C["text2"],
             wraplength=380, justify="left").pack(anchor="w", padx=P, pady=(0, P - 4))
    row = tk.Frame(win, bg=C["bg"])
    row.pack(fill="x", padx=P, pady=(0, P - 4))
    btns = []
    for i, (label, value) in enumerate(buttons):
        def _choose(v=value):
            result["v"] = v
            win.destroy()
        b = FlatButton(row, label, _choose, primary=(i == 0 and not danger),
                       danger=(i == 0 and danger), small=True)
        b.pack(side="right" if i == 0 else "right", padx=(SP["s"], 0))
        btns.append(b)
    win.bind("<Escape>", lambda e: (win.destroy()))
    win.protocol("WM_DELETE_WINDOW", win.destroy)
    win.update_idletasks()
    try:
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        ww, wh = win.winfo_width(), win.winfo_height()
        win.geometry(f"+{px + (pw - ww) // 2}+{py + (ph - wh) // 2}")
    except Exception:
        pass
    # Tk keeps no grab stack: destroying this dialog drops the grab a modal
    # parent (the shares dialog) held, so remember it and hand it back.
    try:
        prev_grab = parent.grab_current()
    except tk.TclError:
        prev_grab = None
    win.grab_set()
    win.focus_force()
    btns[min(default, len(btns) - 1)].focus_set()
    win.wait_window()
    if prev_grab is not None:
        try:
            if prev_grab.winfo_exists():
                prev_grab.grab_set()
        except tk.TclError:
            pass
    return result["v"]


def confirm(parent, title, message, *, yes="Continue", no="Cancel",
            danger=False, default_no=True) -> bool:
    """Themed yes/no.  Destructive actions pass danger=True; the safe button
    holds focus by default so a stray Return never destroys anything."""
    return bool(_dialog(parent, title, message, [(yes, True), (no, False)],
                        danger=danger, default=1 if default_no else 0))


def alert(parent, title, message, *, ok="OK") -> None:
    """Themed single-button message."""
    _dialog(parent, title, message, [(ok, None)])


def reveal_path(path: str) -> bool:
    """Show ``path`` in the platform file manager.  Returns False when no
    handler is available so callers can say so instead of failing silently."""
    import subprocess
    try:
        if sys.platform == "darwin":
            # "--": a self-typed name like -foo.qcx must never read as flags.
            subprocess.Popen(["open", "-R", "--", path])
        elif sys.platform == "win32":
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        else:
            target = path if os.path.isdir(path) else os.path.dirname(path)
            # xdg-open rejects "--" outright, so absolutise instead: an
            # absolute path can never start with a dash.
            subprocess.Popen(["xdg-open", os.path.abspath(target)])
        return True
    except Exception:
        return False


def _find_app_icon() -> str:
    """Return the absolute path to the app icon (.icns or .png), or empty."""
    import os
    # When running from a PyInstaller .app bundle the executable lives at
    # …/quantacrypt.app/Contents/MacOS/quantacrypt  →  Resources is two up.
    exe = os.path.abspath(os.sys.executable)
    resources = os.path.join(os.path.dirname(os.path.dirname(exe)), "Resources")
    for name in ("icon.icns", "icon.png"):
        p = os.path.join(resources, name)
        if os.path.isfile(p):
            return p
    # Fallback: check the source assets directory (running from source)
    src = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "icon.png")
    if os.path.isfile(src):
        return src
    return ""


def _js(s: str) -> str:
    """Escape a Python string for a JavaScript double-quoted literal."""
    return (s.replace("\\", "\\\\").replace('"', '\\"')
             .replace("\n", "\\n").replace("\r", ""))


def _run_jxa(script: str, timeout: float = 5.0):
    """Run a JXA script and return its stdout, or None if it did not run.

    The script travels on stdin, never in argv: a Shamir share passed as a
    command-line argument would be visible in ``ps`` to every process on the
    machine for as long as osascript lives.
    """
    import subprocess
    try:
        r = subprocess.run(["osascript", "-l", "JavaScript", "-"],
                           input=script, text=True, capture_output=True,
                           timeout=timeout)
    except Exception:
        return None
    return r.stdout if r.returncode == 0 else None


# Maccy, Paste, Alfred, Raycast and LaunchBar all check for this marker before
# recording a copy.  Without it a share code lands in a plaintext, searchable
# clipboard history that outlives the app, the file and the volume — somewhere
# QuantaCrypt can never clear it.  Mirrors macos/QuantaCrypt/Shared/Clipboard.swift.
_CONCEALED_TYPE = "org.nspasteboard.ConcealedType"


def copy_secret(widget, text: str):
    """Put key material on the clipboard, hidden from clipboard managers.

    Returns ``(concealed, change)``.  ``change`` is the macOS pasteboard
    changeCount straight after the write, which is the only reliable witness
    that the copy is still ours — Tk keeps answering ``clipboard_get()`` from
    its own stale buffer after another app takes the pasteboard, so comparing
    the text back would happily wipe whatever the user copied since.  Both are
    for ``ClipboardTimer``; ``concealed`` is False when the marker could not be
    written, so the caller can say so instead of implying a protection that
    is not there.

    Raises ``tk.TclError`` if the clipboard cannot be reached at all.
    """
    # Reach the clipboard through Tk first, while there is nothing secret on
    # it: an unreachable clipboard fails here rather than after the share has
    # been handed to a subprocess.  Then hand ownership back — Tkinter cannot
    # declare an NSPasteboard type, so the marked write has to happen outside
    # Tk, and a Tk that still owns the selection would answer clipboard_get()
    # with its own empty buffer instead of the share.
    widget.clipboard_clear()
    widget.clipboard_append("")
    if sys.platform == "darwin":
        try:
            widget.selection_clear(selection="CLIPBOARD")
        except Exception:
            pass
        out = _run_jxa(
            'ObjC.import("AppKit");\n'
            'var pb = $.NSPasteboard.generalPasteboard;\n'
            'pb.clearContents;\n'
            'var it = $.NSPasteboardItem.alloc.init;\n'
            f'it.setStringForType("{_js(text)}", $.NSPasteboardTypeString);\n'
            f'it.setStringForType("", "{_CONCEALED_TYPE}");\n'
            'pb.writeObjects($([it]));\n'
            'String(pb.changeCount);\n')
        if out is not None and out.strip().isdigit():
            return True, int(out.strip())
    widget.clipboard_append(text)
    return False, None


def clear_pasteboard_if_unchanged(change: int):
    """Clear the macOS pasteboard only while ``change`` is still its
    changeCount.  True = cleared, None = the user has copied something else
    since, False = the check could not be run."""
    out = _run_jxa(
        'ObjC.import("AppKit");\n'
        'var pb = $.NSPasteboard.generalPasteboard;\n'
        # changeCount arrives as a string through the ObjC bridge, so === against
        # a numeric literal is always false without the cast.
        f'if (Number(pb.changeCount) === {int(change)}) {{ pb.clearContents; "cleared" }}\n'
        'else { "kept" }\n')
    if out is None:
        return False
    return True if out.strip() == "cleared" else None


def _spawn_osascript(argv: list, script: str) -> None:
    """Start osascript with ``script`` on stdin and return without waiting.

    Same rule as ``_run_jxa``: argv is readable by every local process
    through ``ps``, and a notification quotes file names, mount points and
    failure text — none of which belongs there."""
    import subprocess
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, text=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        proc.stdin.write(script)
    finally:
        proc.stdin.close()


def notify(title: str, message: str, sound: bool = True) -> None:
    """Send a macOS notification if the app window is not in focus.

    Uses osascript with JXA (JavaScript for Automation) to call the native
    NSUserNotification API in a safe subprocess — avoids ctypes/objc_msgSend
    which can SIGSEGV on Apple Silicon.  The notification displays the
    QuantaCrypt app icon when an icon file is found.
    Silently does nothing on non-macOS platforms or if the call fails.
    """
    import sys
    if sys.platform != "darwin":
        return
    try:
        # Check if any app window currently has focus — skip notification if so
        focus = tk.Tk._default_root  # type: ignore[attr-defined]
        if focus and focus.focus_displayof() is not None:
            return
    except Exception:
        pass

    icon_path = _find_app_icon()

    # --- Primary: JXA via osascript (shows app icon) ---
    try:
        jxa = (
            'ObjC.import("Cocoa");\n'
            'var n = $.NSUserNotification.alloc.init;\n'
            f'n.title = "{_js(title)}";\n'
            f'n.informativeText = "{_js(message)}";\n'
        )
        if sound:
            jxa += 'n.soundName = $.NSUserNotificationDefaultSoundName;\n'
        if icon_path:
            jxa += (
                f'var img = $.NSImage.alloc.initByReferencingFile("{_js(icon_path)}");\n'
                'n.setValue(img, {forKey: "contentImage"});\n'  # private but stable
            )
        jxa += '$.NSUserNotificationCenter.defaultUserNotificationCenter'
        jxa += '.deliverNotification(n);\n'
        _spawn_osascript(["osascript", "-l", "JavaScript", "-"], jxa)
        return
    except Exception:
        pass

    # --- Fallback: plain AppleScript (shows Script Editor icon) ---
    try:
        sound_part = ' sound name "Glass"' if sound else ""
        script = (
            f'display notification "{_js(message)}" '
            f'with title "{_js(title)}"{sound_part}'
        )
        _spawn_osascript(["osascript", "-"], script)
    except Exception:
        pass


def fmt_size(n: int) -> str:
    """File size the way Finder and the native shell show it: decimal units.
    Binary units under SI labels read "4.7 GB" here and "5 GB" there for the
    same file."""
    if n < 1000:               return f"{n:,} B"
    if n < 1_000_000:          return f"{n/1000:.1f} KB"
    if n < 1_000_000_000:      return f"{n/1_000_000:.1f} MB"
    return f"{n/1_000_000_000:.1f} GB"


from quantacrypt.core.errors import friendly_error  # noqa: E402  (shared vocabulary lives in core)


def rule(parent, color=None, pady=12, padx=0):
    f = tk.Frame(parent, bg=color or C["border"], height=1)
    f.pack(fill="x", pady=pady, padx=padx)
    return f


def section_label(parent, text, padx=24):
    """Heading row.  Returns the text Label so callers that relabel a
    section later (PASSWORD ↔ SHARES) don't have to dig through children."""
    row = tk.Frame(parent, bg=C["bg"])
    row.pack(fill="x", padx=padx, pady=(18, 6))
    lbl = tk.Label(row, text=text, font=F["small"], bg=C["bg"], fg=C["text3"])
    lbl.pack(side="left")
    tk.Frame(row, bg=C["border"], height=2).pack(
        side="left", fill="x", expand=True, padx=(10,0), pady=1)
    return lbl


try:
    from zxcvbn import zxcvbn as _zxcvbn_fn
except ImportError:
    _zxcvbn_fn = None


class FlatButton(tk.Label):
    """Flat filled button.  States: rest / hover / pressed / focus / disabled.
    Hover and press go DARKER (contrast rises); the focus ring is drawn in
    the text colour on filled buttons so it is visible on the accent."""
    def __init__(self, parent, text, command=None, primary=True,
                 danger=False, small=False, **kw):
        if danger:
            bg, fg, hov, press = C["error_fill"], C["text"], C["error_hover"], C["error_hover"]
        elif primary:
            bg, fg, hov, press = C["accent"], C["text"], C["accent_hover"], C["accent_press"]
        else:
            bg, fg, hov, press = C["surface2"], C["text2"], C["surface3"], C["surface"]

        font = F["small"] if small else F["body_b"]
        padx = SP["m"] if small else SP["l"] + SP["xs"]
        pady = SP["s"] - 2 if small else SP["s"]

        # tk.Label defaults -takefocus to "0", which short-circuits
        # ::tk::FocusOK — so a FlatButton that is never enable()d sits outside
        # the Tab order entirely, including both buttons of every confirm()
        # dialog.  Opt in here; enable(False) still takes it back out.
        kw.setdefault("takefocus", 1)
        super().__init__(parent, text=text, font=font,
                         bg=bg, fg=fg, cursor="hand2",
                         padx=padx, pady=pady, **kw)
        self._cmd = command
        self._bg = bg; self._hov = hov; self._fg = fg; self._press = press
        self._filled = primary or danger
        self._ring = C["text"] if self._filled else C["accent_text"]
        self._enabled = True
        self._bind_live()

    def _fire(self, _e=None):
        if self._cmd:
            self._cmd()
        return "break"

    def _bind_live(self):
        self.bind("<Button-1>",        lambda e: self.config(bg=self._press))
        self.bind("<ButtonRelease-1>", self._release)
        self.bind("<Return>",   self._fire)
        self.bind("<space>",    self._fire)
        self.bind("<Enter>",    lambda e: self.config(bg=self._hov))
        self.bind("<Leave>",    lambda e: self.config(bg=self._bg))
        self.bind("<FocusIn>",  lambda e: self.config(highlightbackground=self._ring,
                                                       highlightcolor=self._ring,
                                                       highlightthickness=2))
        self.bind("<FocusOut>", lambda e: self.config(highlightthickness=0))

    def _release(self, e):
        inside = 0 <= e.x < self.winfo_width() and 0 <= e.y < self.winfo_height()
        self.config(bg=self._hov if inside else self._bg)
        if inside:
            return self._fire()
        return None

    def set_text(self, text):
        self.config(text=text)

    def set_tint(self, on: bool):
        """Secondary button shown as "selected" (accent fill) or at rest.
        The rest colours move too, so hover/leave can't undo the tint."""
        if on:
            self._bg, self._fg, self._hov = C["accent"], C["text"], C["accent_hover"]
        else:
            self._bg, self._fg, self._hov = C["surface2"], C["text2"], C["surface3"]
        if self._enabled:
            self.config(bg=self._bg, fg=self._fg)

    def enable(self, on=True):
        self._enabled = on
        if on:
            self.config(fg=self._fg, cursor="hand2", bg=self._bg, takefocus=1)
            self._bind_live()
            # If mouse is already over the button, apply hover colour immediately
            try:
                x, y = self.winfo_pointerxy()
                wx, wy = self.winfo_rootx(), self.winfo_rooty()
                ww, wh = self.winfo_width(), self.winfo_height()
                if wx <= x <= wx + ww and wy <= y <= wy + wh:
                    self.config(bg=self._hov)
            except Exception:
                pass
        else:
            # Disabled: sinks to the surface colour so it cannot be confused
            # with an enabled secondary button.  Use 'arrow' explicitly —
            # cursor='' may inherit from parent.
            self.config(fg=C["text3"], cursor="arrow", bg=C["surface"], takefocus=0,
                        highlightthickness=0)
            for ev in ("<Button-1>", "<ButtonRelease-1>", "<Return>", "<space>",
                       "<Enter>", "<Leave>", "<FocusIn>", "<FocusOut>"):
                self.bind(ev, lambda e: None)


class SegmentedControl(tk.Frame):
    """Pill-style mode toggle with keyboard navigation."""
    def __init__(self, parent, options, variable, **kw):
        super().__init__(parent, bg=C["surface"],
                         highlightbackground=C["border"],
                         highlightthickness=1, **kw)
        self._var = variable
        self._opt_vals = [val for val, _ in options]
        self._labels = {}
        for i, (val, text) in enumerate(options):
            lbl = tk.Label(self, text=text, font=F["body_b"],
                           padx=0, pady=10, cursor="hand2")
            lbl.grid(row=0, column=i, sticky="nsew")
            self.columnconfigure(i, weight=1)
            lbl.bind("<Button-1>", lambda e, v=val: variable.set(v))
            self._labels[val] = lbl
        # Keep the trace id so destroy() can detach it. A trace added to a
        # caller-owned variable outlives this widget: the variable survives,
        # the callback keeps firing against a destroyed control, and the next
        # widget sharing that variable sees ghost refreshes.
        self._variable = variable
        self._trace_id = variable.trace_add("write", lambda *_: self._refresh())
        self._refresh()

        # Keyboard: Tab focuses the control, Left/Right arrows switch options
        self.config(takefocus=True)
        self.bind("<FocusIn>",  lambda e: self.config(highlightbackground=C["accent_text"], highlightthickness=2))
        self.bind("<FocusOut>", lambda e: self.config(highlightbackground=C["border"], highlightthickness=1))
        self.bind("<Left>",  lambda e: self._step(-1))
        self.bind("<Right>", lambda e: self._step(1))
        self.bind("<Return>", lambda e: None)  # absorb so form doesn't submit on focus

    def set_enabled(self, on: bool):
        """Freeze/thaw: blocks clicks and arrow keys, dims labels, and
        drops the control from the Tab order while a job runs."""
        self._enabled = on
        for val, lbl in self._labels.items():
            if on:
                lbl.config(cursor="hand2")
                lbl.bind("<Button-1>", lambda e, v=val: self._var.set(v))
            else:
                lbl.config(cursor="arrow")
                lbl.bind("<Button-1>", lambda e: None)
        if on:
            self.bind("<Left>",  lambda e: self._step(-1))
            self.bind("<Right>", lambda e: self._step(1))
            self.config(takefocus=True)
            self._refresh()
        else:
            self.unbind("<Left>"); self.unbind("<Right>")
            self.config(takefocus=0)
            for lbl in self._labels.values():
                lbl.config(fg=C["text3"])

    def _step(self, direction):
        opts = self._opt_vals
        try:
            idx = opts.index(self._var.get())
        except ValueError:
            idx = 0
        self._var.set(opts[(idx + direction) % len(opts)])

    def _refresh(self):
        v = self._var.get()
        for val, lbl in self._labels.items():
            lbl.config(bg=C["accent"] if val==v else C["surface"],
                       fg=C["text"]   if val==v else C["text3"])


    def destroy(self):
        """Detach the write trace before going away.

        Without this the callback keeps firing against a destroyed widget for
        as long as the caller's variable lives — which for the decryptor's
        share-mode toggle means every rebuilt control adds another trace and
        none are ever removed.
        """
        try:
            if getattr(self, "_trace_id", None) is not None:
                self._variable.trace_remove("write", self._trace_id)
                self._trace_id = None
        except Exception:
            pass          # the interpreter may already be tearing down
        super().destroy()


class StagedProgressBar(tk.Frame):
    """
    A real progress bar that tracks named stages.
    Shows: [=====>      ] Stage name  2.1s / ~3.5s
    """
    def __init__(self, parent, stages, **kw):
        """
        stages: list of (name, weight) tuples, weights relative (sum = 1.0)
        """
        super().__init__(parent, bg=C["surface"],
                         highlightbackground=C["border"],
                         highlightthickness=1, **kw)
        self._stages    = stages          # [(name, weight), ...]
        self._current   = -1
        self._pct       = 0.0             # 0.0 – 1.0
        self._start_t   = None
        self._stage_t   = None
        self._total_est = None
        self._running   = False
        self._pulse_base = None  # base label text for animated dot pulse
        self._pulse_job  = None  # pending after() id for pulse
        self._time_job   = None  # pending after() id for the ETA loop
        self._bar_w      = 0     # canvas width from the last <Configure>
        self._stage_pcts = self._build_stage_pcts()

        # Stage name label
        self._stage_lbl = tk.Label(self, text="", font=F["body_b"],
                                   bg=C["surface"], fg=C["text"])
        self._stage_lbl.pack(anchor="w", padx=16, pady=(12, 4))

        # Progress bar canvas
        self._bar_cv = tk.Canvas(self, height=6, bg=C["surface2"],
                                  highlightthickness=0)
        self._bar_cv.pack(fill="x", padx=16, pady=(0, 6))
        self._bar_cv.bind("<Configure>", self._on_bar_configure)

        # Bottom row: stage progress + time
        bottom = tk.Frame(self, bg=C["surface"])
        bottom.pack(fill="x", padx=16, pady=(0, 12))

        self._pct_lbl  = tk.Label(bottom, text="", font=F["caption"],
                                   bg=C["surface"], fg=C["text2"])
        self._pct_lbl.pack(side="left")

        self._time_lbl = tk.Label(bottom, text="", font=F["caption"],
                                   bg=C["surface"], fg=C["text3"])
        self._time_lbl.pack(side="right")

        # Stage dots row
        self._dots_frame = tk.Frame(self, bg=C["surface"])
        self._dots_frame.pack(fill="x", padx=16, pady=(0, 14))
        self._dot_cvs = []
        self._connector_cvs = []  # dynamic colour connectors
        for i, (name, _) in enumerate(stages):
            cv = tk.Canvas(self._dots_frame, width=8, height=8,
                           bg=C["surface"], bd=0, highlightthickness=0)
            cv.pack(side="left", padx=(0, 4))
            self._dot_cvs.append(cv)
            if i < len(stages) - 1:
                # Use Canvas so colour can be updated as stages complete
                con = tk.Canvas(self._dots_frame, width=20, height=2,
                                bg=C["border"], bd=0, highlightthickness=0)
                con.pack(side="left", pady=3)
                self._connector_cvs.append(con)

        self._draw_dots()

    def _build_stage_pcts(self):
        """Pre-compute cumulative percentage at start of each stage."""
        total = sum(w for _, w in self._stages)
        pcts = []
        acc = 0.0
        for _, w in self._stages:
            pcts.append(acc / total)
            acc += w
        return pcts

    def _cancel_jobs(self):
        for attr in ("_time_job", "_pulse_job"):
            job = getattr(self, attr)
            if job is not None:
                try:
                    self.after_cancel(job)
                except Exception:
                    pass
                setattr(self, attr, None)

    def start(self):
        self._cancel_jobs()
        self._start_t = time.time()
        self._stage_t = time.time()
        self._running = True
        # Reset all visual state so a second operation doesn't inherit stale
        # "Complete" label/colours from a previous run
        self._current  = -1
        self._pct      = 0.0
        self._pulse_base = None
        self._stage_lbl.config(text="Starting…", fg=C["text"])
        self._pct_lbl.config(text="0%", fg=C["text2"])
        self._time_lbl.config(text="", fg=C["text3"])
        self._draw_bar()
        self._draw_dots()
        # The one and only ETA loop for this run — advance() must never
        # start another (one per 4 MB chunk used to pile up on big files).
        self._update_time()

    def advance(self, stage_idx, stage_name=None):
        """Called when a new stage begins or progresses.

        If stage_name contains a percentage like '... 45%', the progress bar
        interpolates within the stage rather than staying pinned at the start.
        """
        if stage_idx != self._current:
            # New stage — reset stage timer
            self._stage_t = time.time()
        self._current  = stage_idx
        name = stage_name or (self._stages[stage_idx][0] if stage_idx < len(self._stages) else "")
        self._stage_lbl.config(text=name)
        self._pulse_base = name  # base text for animated dots

        # Parse sub-progress from messages like "Encrypting payload... 45%"
        stage_start = self._stage_pcts[stage_idx] if stage_idx < len(self._stage_pcts) else 1.0
        if stage_idx + 1 < len(self._stage_pcts):
            stage_end = self._stage_pcts[stage_idx + 1]
        else:
            stage_end = 1.0
        sub_pct = 0.0
        if stage_name:
            import re
            m = re.search(r'(\d+)%', stage_name)
            if m:
                sub_pct = min(int(m.group(1)) / 100.0, 1.0)
        self._pct = stage_start + sub_pct * (stage_end - stage_start)

        self._draw_bar()
        self._draw_dots()
        self._refresh_time_labels()
        # Restart the dot pulse for this stage (cancelling the previous one)
        if self._pulse_job is not None:
            try: self.after_cancel(self._pulse_job)
            except Exception: pass
            self._pulse_job = None
        self._pulse_tick(0)

    def stop(self):
        """Halt the timer loop without marking as complete (used on failure/reset)."""
        self._running = False
        self._pulse_base = None  # stop pulse loop
        self._cancel_jobs()

    def complete(self):
        self._pct = 1.0
        self._running = False
        self._pulse_base = None  # stop pulse loop
        self._cancel_jobs()
        elapsed = time.time() - self._start_t if self._start_t else 0
        self._stage_lbl.config(text="Complete", fg=C["success"])
        self._pct_lbl.config(text="100%", fg=C["success"])
        self._time_lbl.config(text=f"{elapsed:.1f}s", fg=C["success"])
        self._draw_bar(complete=True)
        self._draw_dots(complete=True)

    def destroy(self):
        self._cancel_jobs()
        super().destroy()

    def _on_bar_configure(self, event):
        self._bar_w = event.width
        self._draw_bar(complete=(not self._running and self._pct >= 1.0))

    def _draw_bar(self, complete=False):
        # Width comes from the last <Configure>; no update_idletasks() here —
        # this runs once per progress message and must not pump the event loop.
        w = self._bar_w
        if w < 2: return
        self._bar_cv.delete("all")
        # Background
        self._bar_cv.create_rectangle(0, 0, w, 6, fill=C["surface2"], outline="")
        # Fill
        fill_w = int(w * self._pct)
        if fill_w > 0:
            col = C["success"] if complete else C["accent"]
            self._bar_cv.create_rectangle(0, 0, fill_w, 6, fill=col, outline="")

    def _draw_dots(self, complete=False):
        for i, cv in enumerate(self._dot_cvs):
            cv.delete("all")
            if complete or i < self._current:
                col = C["success"]
            elif i == self._current:
                col = C["accent"]
            else:
                col = C["surface3"]
            cv.create_oval(0, 0, 8, 8, fill=col, outline="")
        # Update connector colour — green when left stage is done
        for i, con in enumerate(self._connector_cvs):
            done = complete or i < self._current
            con.config(bg=C["success"] if done else C["border"])

    def _update_time(self):
        """250 ms ETA loop.  Scheduled from start() only; every tick
        re-arms itself so there is exactly one pending job at a time."""
        self._time_job = None
        if not self._running or not self._start_t: return
        self._refresh_time_labels()
        if self._running and self._pct < 1.0:
            self._time_job = self.after(250, self._update_time)

    def _refresh_time_labels(self):
        if not self._running or not self._start_t: return
        now = time.time()
        pct = self._pct
        if pct > 0.01:
            # Use stage-local rate for estimation when inside a stage with progress.
            # This avoids the early slow stages (Argon2id) polluting the estimate
            # once the fast payload stage begins.
            stage_idx = self._current
            stage_start_pct = self._stage_pcts[stage_idx] if stage_idx < len(self._stage_pcts) else 0.0
            pct_within_stage = pct - stage_start_pct
            stage_elapsed = now - self._stage_t

            if pct_within_stage > 0.005 and stage_elapsed > 0.5:
                # Estimate remaining from current stage's rate
                rate = pct_within_stage / stage_elapsed  # pct per second
                remaining = max(0, (1.0 - pct) / rate)
            else:
                # Fallback: whole-job linear extrapolation for early moments
                elapsed = now - self._start_t
                est_total = elapsed / pct
                remaining = max(0, est_total - elapsed)

            self._pct_lbl.config(text=f"{int(pct*100)}%")
            if remaining > 0.5:
                self._time_lbl.config(text=f"~{remaining:.0f}s left")
            else:
                self._time_lbl.config(text="almost done...")
        else:
            self._pct_lbl.config(text="0%")
            self._time_lbl.config(text="calculating...")

    def _pulse_tick(self, dot_count):
        """Animate a cycling '…' suffix on the stage label when there is no
        sub-progress to display (pct == 0, e.g. during the Argon2id KDF stage).
        Stops automatically when _pulse_base is cleared by advance/stop/complete."""
        self._pulse_job = None
        if self._pulse_base is None: return          # stopped
        if self._pct > 0.01:                         # real progress arrived — stop pulse
            self._stage_lbl.config(text=self._pulse_base)
            return
        dots = "." * ((dot_count % 3) + 1)
        try:
            self._stage_lbl.config(text=self._pulse_base.rstrip(".… ") + dots)
        except Exception:
            pass
        self._pulse_job = self.after(450, self._pulse_tick, dot_count + 1)


class PasswordStrengthBar(tk.Frame):
    """Live password strength estimator using zxcvbn for realistic scoring.

    zxcvbn is super-linear in the password length (a long passphrase costs
    hundreds of ms in pure Python), so scoring runs on a worker thread and
    the result is applied on the main thread; a stale result for text the
    user has since changed is dropped.  ``score_for()`` lets the submit
    path reuse the last score instead of blocking the window again."""
    _LABELS = ["Very Weak", "Weak", "Fair", "Good", "Strong"]

    def __init__(self, parent, entry_var, **kw):
        super().__init__(parent, bg=C["bg"], **kw)
        self._var = entry_var

        bar_row = tk.Frame(self, bg=C["bg"])
        bar_row.pack(fill="x")

        self._bar_cv = tk.Canvas(bar_row, height=3, bg=C["surface2"],
                                  highlightthickness=0)
        self._bar_cv.pack(side="left", fill="x", expand=True)
        self._bar_w = 0
        self._bar_cv.bind("<Configure>", self._on_configure)

        self._lbl = tk.Label(bar_row, text="", font=F["small"],
                              bg=C["bg"], fg=C["text3"], width=8, anchor="e")
        self._lbl.pack(side="left", padx=(8,0))

        self._tip = tk.Label(self, text=" ", font=F["small"],  # pre-allocated height
                              bg=C["bg"], fg=C["text3"], anchor="w",
                              wraplength=400, justify="left")
        self._tip.pack(fill="x", pady=(2,0))

        self._refresh_job = None  # debounce handle
        self._seq = 0             # request counter — stale worker results are dropped
        self._last = ("", 0, "", "")   # (pw, score, label, tip) of the last applied result
        # One scoring thread per bar, fed through a queue that is drained to
        # the newest request (a burst of pauses used to spawn one zxcvbn run
        # each).  ``_inflight`` lets score_for() wait briefly for the result
        # of the text on screen instead of scoring on the main thread.
        self._queue: "queue.Queue" = queue.Queue()
        self._thread: threading.Thread | None = None
        self._inflight: tuple[str, threading.Event, dict] | None = None
        # Same reason as SegmentedControl: detach on destroy.
        self._entry_var = entry_var
        self._trace_id = entry_var.trace_add(
            "write", lambda *_: self._schedule_refresh())

    def destroy(self):
        """Detach the trace and cancel the debounce before going away."""
        try:
            if getattr(self, "_trace_id", None) is not None:
                self._entry_var.trace_remove("write", self._trace_id)
                self._trace_id = None
        except Exception:
            pass
        try:
            if getattr(self, "_refresh_job", None) is not None:
                self.after_cancel(self._refresh_job)
                self._refresh_job = None
        except Exception:
            pass
        super().destroy()

    def _on_configure(self, event):
        self._bar_w = event.width
        self._draw(self._last[1], self._last[0])

    def _schedule_refresh(self):
        """Debounce — score 150 ms after the last keystroke."""
        if self._refresh_job is not None:
            try: self.after_cancel(self._refresh_job)
            except Exception: pass
        self._refresh_job = self.after(150, self._refresh)

    def _score(self, pw):
        if not pw: return 0, "", ""
        if _zxcvbn_fn is not None:
            # zxcvbn caps input at 72 characters (raises above it, and is
            # super-linear below it) — score the prefix, like the estimator
            # itself does; anything that long is not weak for its length.
            r = _zxcvbn_fn(pw[:72])
            score = r["score"]  # 0-4
            fb = r.get("feedback", {})
            tips = []
            if fb.get("warning"): tips.append(fb["warning"])
            tips.extend(fb.get("suggestions", [])[:1])
            tip = tips[0] if tips else ""
            return score, self._LABELS[score], tip
        else:
            # Fallback entropy estimator when zxcvbn is not installed
            import math, re
            pool = sum([26 if re.search(p, pw) else 0
                        for p in [r'[a-z]', r'[A-Z]']] +
                       [10 if re.search(r'[0-9]', pw) else 0,
                        32 if re.search(r'[^a-zA-Z0-9]', pw) else 0])
            e = len(pw) * math.log2(pool) if pool else 0
            s = 1 if e < 28 else 2 if e < 36 else 3 if e < 60 else 4
            return s, self._LABELS[s], ""

    _SUBMIT_WAIT_S = 0.3   # how long score_for() waits for an in-flight result

    def score_for(self, pw) -> int:
        """0-4 for ``pw``.  The cached result when it is the text on screen
        (the usual case at submit).  A fast typist who presses Return inside
        the debounce window (or before the worker returned) gets the worker
        kicked now and a short wait for ITS result; if that is still not in,
        the last applied score is used — never a synchronous zxcvbn run on
        the main thread."""
        if pw == self._last[0]:
            return self._last[1]
        if self._refresh_job is not None:
            try:
                self.after_cancel(self._refresh_job)
            except Exception:
                pass
            self._refresh_job = None
            self._refresh()
        inflight = self._inflight
        if inflight is not None and inflight[0] == pw:
            _pw, ev, holder = inflight
            if ev.wait(self._SUBMIT_WAIT_S) and "res" in holder:
                score, label, tip = holder["res"]
                self._apply(holder["seq"], pw, score, label, tip)
                return score
        return self._last[1]

    def _refresh(self):
        self._refresh_job = None
        pw = self._var.get()
        self._seq += 1
        seq = self._seq
        if not pw:
            self._inflight = None
            self._apply(seq, pw, 0, "", "")
            return
        holder = {"seq": seq}
        ev = threading.Event()
        self._inflight = (pw, ev, holder)
        self._queue.put((seq, pw, ev, holder))
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._worker_loop, daemon=True)
            self._thread.start()

    def _worker_loop(self):
        """Scores the newest queued request; exits after a few idle seconds
        so a closed window doesn't keep a thread parked forever."""
        while True:
            try:
                item = self._queue.get(timeout=5)
            except queue.Empty:
                return
            while True:   # drain: only the newest text matters
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
            seq, pw, ev, holder = item
            try:
                res = self._score(pw)
            except Exception:
                res = (0, "", "")
            holder["res"] = res
            ev.set()
            score, label, tip = res
            safe_after(self, lambda s=seq, p=pw, r=res: self._apply(s, p, *r))

    def _apply(self, seq, pw, score, label, tip):
        if seq != self._seq:
            return  # a newer keystroke superseded this result
        self._last = (pw, score, label, tip)
        self._lbl.config(text=label, fg=self._colour(score, pw))
        self._tip.config(text=tip)
        self._draw(score, pw)

    @staticmethod
    def _colour(score, pw):
        # Quality ramp only — the action blue is not a grade.
        colors = [C["error"], C["error"], C["warning"], C["success"], C["success"]]
        return colors[score] if pw else C["surface3"]

    def _draw(self, score, pw):
        w = self._bar_w
        if w < 2: return
        self._bar_cv.delete("all")
        self._bar_cv.create_rectangle(0, 0, w, 3, fill=C["surface2"], outline="")
        fill = int(w * score / 4)
        if fill > 0:
            self._bar_cv.create_rectangle(0, 0, fill, 3, fill=self._colour(score, pw), outline="")


class FileCard(tk.Frame):
    """Consolidated drop-zone / file picker used by both encryptor and decryptor.

    Parameters
    ----------
    parent      : tk widget
    on_select   : callable(path) — fired when a file is chosen
    on_folder   : callable(path) — fired when a folder is chosen in folder
                  mode (falls back to on_select when not given)
    prompt      : str  — headline text before selection
    sub         : str  — subtext / accepted types hint
    filetypes   : list of (label, pattern) for the file dialog
    """

    def __init__(self, parent, on_select, *,
                 on_folder=None,
                 prompt="Select a file",
                 sub="Click anywhere in this box",
                 filetypes=None,
                 **kw):
        super().__init__(parent, bg=C["surface"],
                         highlightbackground=C["border"], highlightthickness=1,
                         cursor="hand2", **kw)
        self._cb        = on_select
        self._on_folder = on_folder
        self._folder_mode = False
        self._selected  = False
        self._filetypes = filetypes or [("All files", "*")]

        self._icon  = tk.Label(self, text="+", font=F["hero"],
                                bg=C["surface"], fg=C["surface3"])
        self._icon.pack(pady=(SP["l"], SP["xs"]))
        self._line1 = tk.Label(self, text=prompt,
                                font=F["body_b"], bg=C["surface"], fg=C["text3"])
        self._line1.pack()
        self._line2 = tk.Label(self, text=sub,
                                font=F["caption"], bg=C["surface"], fg=C["text3"])
        self._line2.pack(pady=(2, 20))

        for w in [self, self._icon, self._line1, self._line2]:
            w.bind("<Button-1>", lambda e: self._pick())
        # Bind hover only on self (Frame) to avoid flicker when cursor
        # crosses child label boundaries (each child fires its own Enter/Leave)
        self.bind("<Enter>", lambda e: self._hl(True))
        self.bind("<Leave>", lambda e: self._hl(False))

        # Keyboard accessibility: Tab can focus the card, Enter/Space activates it
        self.config(takefocus=True)
        self.bind("<Return>", lambda e: self._pick())
        self.bind("<space>",  lambda e: self._pick())
        self.bind("<FocusIn>",  lambda e: self.config(
            highlightbackground=C["accent_text"],
            highlightthickness=2))
        self.bind("<FocusOut>", lambda e: self.config(
            highlightbackground=C["success"] if self._selected else C["border"],
            highlightthickness=1))

    def set_drop_supported(self, supported: bool, sub_with_drop: str, sub_without: str):
        """Only promise drag & drop when the caller actually registered a
        drop target — otherwise the hint is a lie."""
        if not self._selected:
            self._line2.config(text=sub_with_drop if supported else sub_without)
        self._sub_default = sub_with_drop if supported else sub_without

    def set_folder_mode(self, on: bool):
        """Clicking the card asks for a folder (→ ``on_folder``) instead of a file."""
        self._folder_mode = bool(on)

    def _pick(self):
        from tkinter import filedialog
        if self._folder_mode:
            p = filedialog.askdirectory()
            if p:
                (self._on_folder or self._cb)(p)
        else:
            import os as _os
            p = filedialog.askopenfilename(
                filetypes=self._filetypes,
                initialdir=_os.path.expanduser("~"))
            if p:
                self.load(p)
                self._cb(p)

    def load(self, path):
        """Pre-populate card (used when app is launched with a file argument)."""
        self._selected = True
        self._icon.config(text=ICON["ok"], fg=C["success"])
        self._line1.config(text=os.path.basename(path), fg=C["text"], font=F["body_b"])
        try:
            size_str = fmt_size(os.path.getsize(path))
        except OSError:
            size_str = "unknown size"
        self._line2.config(text=f"{size_str}  ·  Click to change",
                           fg=C["accent_text"])
        for w in [self, self._icon, self._line1, self._line2]:
            w.config(bg=C["surface"])
        self.config(highlightbackground=C["success"])

    def load_folder(self, path, count: int, total_bytes: int, *, scanning=False):
        """Folder state.  ``scanning=True`` shows the interim label while a
        worker walks the tree; call again with the totals when done."""
        self._selected = True
        self._icon.config(text=ICON["ok"], fg=C["success"])
        self._line1.config(text=os.path.basename(path.rstrip(os.sep)) or path,
                           fg=C["text"], font=F["body_b"])
        if scanning:
            self._line2.config(text="Scanning folder…", fg=C["text3"])
        else:
            self._line2.config(
                text=f"{count:,} files  ·  {fmt_size(total_bytes)}  ·  Click to change",
                fg=C["accent_text"])
        for w in [self, self._icon, self._line1, self._line2]:
            w.config(bg=C["surface"])
        self.config(highlightbackground=C["success"])

    def set_enabled(self, on: bool):
        """Freeze/thaw without callers touching private widgets."""
        self.config(takefocus=bool(on), cursor="hand2" if on else "arrow")
        for w in [self, self._icon, self._line1, self._line2]:
            if on:
                w.bind("<Button-1>", lambda e: self._pick())
            else:
                w.bind("<Button-1>", lambda e: None)

    def reset(self, prompt, sub=None):
        """Restore to unselected state (used by _reset flows)."""
        self._selected = False
        self._icon.config(text="+", fg=C["surface3"])
        self._line1.config(text=prompt, fg=C["text3"], font=F["body_b"])
        self._line2.config(text=sub if sub is not None
                           else getattr(self, "_sub_default", ""), fg=C["text3"])
        for w in [self, self._icon, self._line1, self._line2]:
            w.config(bg=C["surface"])
        self.config(highlightbackground=C["border"])

    def _hl(self, on):
        if self._selected: return
        col = C["surface2"] if on else C["surface"]
        for w in [self, self._icon, self._line1, self._line2]:
            w.config(bg=col)


class WizardSteps(tk.Canvas):
    """Horizontal step tracker. Steps: list of names. Active = current step."""
    def __init__(self, parent, steps, **kw):
        nsteps = len(steps)
        super().__init__(parent, width=nsteps*100, height=56,
                         bg=C["bg"], bd=0, highlightthickness=0, **kw)
        self._steps  = steps
        self._active = 0
        self._min_w  = nsteps * 100  # renamed: self._w is reserved by Tkinter for widget path
        self.config(takefocus=0)  # informational only — skip in Tab order
        self.bind("<Configure>", lambda e: self._draw())
        self._draw()

    def set_step(self, n):
        self._active = n
        self._draw()

    def _draw(self):
        self.delete("all")
        n  = len(self._steps)
        self.update_idletasks()
        w  = max(self.winfo_width(), self._min_w)
        sw = w // n
        cy = 22
        r  = 10

        for i, name in enumerate(self._steps):
            cx     = i * sw + sw // 2
            # When _active is set past the last step index, all steps are "done"
            done   = i < self._active
            active = i == self._active

            # Connector line
            if i < n - 1:
                lx = cx + r + 4
                rx = (i+1) * sw + sw//2 - r - 4
                self.create_line(lx, cy, rx, cy,
                                 fill=C["success"] if done else C["border"], width=1)

            # Done circles use success green (matches connectors)
            if done:
                self.create_oval(cx-r, cy-r, cx+r, cy+r,
                                  fill=C["success"], outline="")
                self.create_text(cx, cy, text=ICON["ok"], font=F["small"],
                                  fill=C["bg"])
            elif active:
                self.create_oval(cx-r, cy-r, cx+r, cy+r,
                                  fill=C["accent"], outline="")
                self.create_text(cx, cy, text=str(i+1), font=F["small"],
                                  fill=C["text"])
            else:
                self.create_oval(cx-r, cy-r, cx+r, cy+r,
                                  fill=C["surface2"], outline=C["border"], width=1)
                self.create_text(cx, cy, text=str(i+1), font=F["small"],
                                  fill=C["text3"])

            # Label below — truncate if too wide for its slot
            max_chars = max(6, sw // 8)
            label_text = name if len(name) <= max_chars else name[:max_chars-1] + "…"
            self.create_text(cx, cy+r+10, text=label_text, font=F["small"], anchor="n",
                              fill=C["success"] if done else
                              (C["accent_text"] if active else C["text3"]))


class ClipboardTimer:
    """Auto-clears the clipboard after `seconds` and shows a countdown label.

    Usage:
        timer = ClipboardTimer(widget, label_widget, seconds=60)
        timer.copy(widget, share)   # copies, conceals, arms the countdown
        timer.cancel()    # call if the user manually clears or copies something else

    The label_widget text is updated every second: "Clipboard clears in 42s"
    When the timer fires, the clipboard is cleared and the label reset.

    The wipe only ever removes the copy this timer made.  The clipboard is
    shared with every other app on the machine, so a timer that cleared it
    unconditionally would destroy whatever the user copied in the meantime —
    an account number out of Safari at t=20 is gone at t=60.
    """
    _SECS = 60
    #: Every timer with a copy still on the clipboard, for wipe_all().
    _armed: "set[ClipboardTimer]" = set()

    @classmethod
    def wipe_all(cls):
        """Clear every armed copy now.  For a quit: the countdown dies with
        the process, and "the clipboard clears in 60 s" must stay true."""
        for timer in list(cls._armed):
            if timer._job is not None:
                try: timer._root.after_cancel(timer._job)
                except Exception: pass
                timer._job = None
            timer._remain = 0
            try:
                timer._wipe()
            finally:
                timer._written = None
                timer._change  = None
                cls._armed.discard(timer)

    def __init__(self, root, label, seconds=60):
        self._root   = root    # any Tk widget with after()/clipboard_clear()
        self._label  = label
        self._secs   = seconds
        self._job    = None
        self._remain = 0
        self._written   = None   # what this timer put on the clipboard
        self._change    = None   # macOS pasteboard changeCount for that write
        self._concealed = True

    def copy(self, widget, text):
        """Copy `text` as key material and arm the countdown.  Returns False
        when the concealed-pasteboard marker could not be written."""
        concealed, change = copy_secret(widget, text)
        self.start(text, concealed=concealed, change=change)
        return concealed

    def start(self, value=None, *, concealed=True, change=None):
        """`value` is the text just placed on the clipboard.  Without it the
        clipboard is read back instead, which is what the caller has just
        written — but a caller that knows should say so."""
        self.cancel()
        self._written   = value if value is not None else self._clipboard_text()
        self._change    = change
        self._concealed = concealed
        self._remain = self._secs
        ClipboardTimer._armed.add(self)
        self._tick()

    def _clipboard_text(self):
        """The text really on the system clipboard, or None."""
        if sys.platform == "darwin":
            # Tk answers from its own buffer while it owns the selection, and
            # on macOS it never notices another app taking the pasteboard.
            import subprocess
            try:
                r = subprocess.run(["pbpaste"], capture_output=True, text=True,
                                   timeout=5)
                return r.stdout if r.returncode == 0 else None
            except Exception:
                return None
        try:
            return self._root.clipboard_get()
        except Exception:
            return None

    def cancel(self):
        if self._job is not None:
            try: self._root.after_cancel(self._job)
            except Exception: pass
            self._job = None
        self._remain = 0
        # Forget the copy too, so a later _clear can never act on a stale one.
        self._written = None
        self._change  = None
        ClipboardTimer._armed.discard(self)
        try:
            self._set_label("")
        except Exception: pass

    def detach_label(self):
        """Blank and forget the countdown label, keeping the wipe armed.

        For a card that has just been saved: the share is still on the
        clipboard, and this timer's wipe is the only thing that will ever
        take it off.  ``cancel()`` would forget the copy along with the
        label."""
        try:
            self._set_label("")
        except Exception: pass
        self._label = None

    def _set_label(self, text, **kw):
        if self._label is not None and self._label.winfo_exists():
            self._label.config(text=text, **kw)

    def _tick(self):
        if self._remain <= 0:
            self._clear()
            return
        # Say so when the copy is unmarked: on that path a clipboard manager
        # keeps the share for ever and the countdown protects nothing.
        note = "" if self._concealed else "  ·  a clipboard manager may keep it"
        try:
            self._set_label(f"Clipboard clears in {self._remain}s{note}", fg=C["text3"])
        except Exception:
            return
        self._remain -= 1
        self._job = self._root.after(1000, self._tick)

    def _wipe(self):
        """True cleared / None deliberately left alone / False tried and failed."""
        if self._change is not None:
            return clear_pasteboard_if_unchanged(self._change)
        if self._written is None:
            # Nothing was recorded, so nothing on the clipboard is known to be
            # ours and there is no safe wipe to make.
            return None
        if self._clipboard_text() != self._written:
            return None
        try:
            self._root.clipboard_clear()
        except Exception:
            return False
        return True

    def _clear(self):
        self._job = None
        outcome = self._wipe()
        # This copy is settled either way; never act on it a second time.
        self._written = None
        self._change  = None
        ClipboardTimer._armed.discard(self)
        if outcome is True:
            text, fg, fade = f"Clipboard cleared {ICON['ok']}", C["success"], True
        elif outcome is None:
            text, fg, fade = "Clipboard already changed", C["text3"], True
        else:
            # Never claim a wipe that did not happen: for a Shamir share the
            # claim is the whole security story, and the user has to know to
            # clear it themselves.
            text, fg, fade = (f"Couldn't clear the clipboard {ICON['warn']}",
                              C["warning"], False)
        try:
            self._set_label(text, fg=fg)
            if fade:
                self._root.after(2000, lambda: self._set_label(""))
        except Exception: pass


def _data_dir() -> str:
    if sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    elif sys.platform == "win32":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
    else:
        base = os.environ.get("XDG_DATA_HOME",
                              os.path.expanduser("~/.local/share"))
    d = os.path.join(base, "QuantaCrypt")
    # The stores under it list every file decrypted and volume mounted.
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def _write_private_json(path: str, data) -> None:
    """Dump ``data`` to ``path`` through a 0600 temp file beside it.  The
    rename is atomic, so a crash mid-write keeps the previous store rather
    than a truncated one, and the umask never widens what the file holds."""
    import json
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix=".", suffix=".tmp",
                               dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class RecentFiles:
    """Persist recently used .qcx files between sessions.

    Pure-classmethods API so callers don't need to instantiate; the storage
    path is a class attribute (``_PATH``) making it trivial to monkeypatch
    in tests.

    ``load()`` returns a list of (path, meta_dict) tuples ordered most-recent
    first, filtered to files that still exist on disk.

    ``add(path, meta=None)`` inserts/bumps an entry and persists immediately.
    ``remove(path)`` removes a single entry.
    ``clear()`` wipes the list.
    """
    MAX_ITEMS = 10
    _PATH: str = ""   # resolved lazily so tests can monkeypatch before first use
    _FILENAME = "recent.json"

    # ── Internal helpers ──────────────────────────────────────────────────────

    @classmethod
    def _resolve_path(cls):
        if cls._PATH:
            return cls._PATH
        return os.path.join(_data_dir(), cls._FILENAME)

    @classmethod
    def _read_raw(cls):
        import json
        try:
            with open(cls._resolve_path()) as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
        except Exception:
            pass
        return []

    @classmethod
    def _write_raw(cls, entries):
        """True when the list is on disk.  "Clear" must not report a list of
        decrypted-file paths gone while it is still stored (run 18 F-208)."""
        try:
            _write_private_json(cls._resolve_path(), entries)
        except Exception:
            return False
        return True

    @staticmethod
    def _well_formed(raw):
        """Only entries whose path is a string: the store is user-editable,
        and ``os.path.isfile(None)`` is a TypeError, not a missing file."""
        return [e for e in raw if isinstance(e, dict) and isinstance(e.get("path"), str)]

    # ── Public API ────────────────────────────────────────────────────────────

    @classmethod
    def load(cls):
        """Return list of (path, meta_dict) tuples, newest first, existing only."""
        raw = cls._read_raw()
        valid = [(e["path"], e) for e in cls._well_formed(raw)
                 if os.path.isfile(e["path"])]
        # Persist filtered list if anything was trimmed
        if len(valid) != len(raw):
            cls._write_raw([e for _, e in valid])
        return valid

    @classmethod
    def add(cls, path, meta=None):
        """Insert path at front, deduplicate, trim to MAX_ITEMS, save."""
        import time
        raw = [e for e in cls._well_formed(cls._read_raw()) if e["path"] != path]
        entry = {"path": path, "ts": time.time()}
        if meta:
            entry["mode"]      = meta.get("mode", "single")
            entry["threshold"] = meta.get("threshold", 0)
            entry["total"]     = meta.get("total", 0)
        raw.insert(0, entry)
        cls._write_raw(raw[:cls.MAX_ITEMS])

    @classmethod
    def remove(cls, path):
        raw = [e for e in cls._well_formed(cls._read_raw()) if e["path"] != path]
        cls._write_raw(raw)

    @classmethod
    def clear(cls):
        return cls._write_raw([])


class RecentVolumes(RecentFiles):
    """Recently mounted .qcv files — separate list from .qcx recents."""
    _PATH: str = ""
    _FILENAME = "recent-volumes.json"


class AppPrefs:
    """Tiny persisted key/value store (dismissed update tag, etc.)."""
    _PATH: str = ""

    @classmethod
    def _resolve_path(cls):
        return cls._PATH or os.path.join(_data_dir(), "prefs.json")

    @classmethod
    def _read(cls) -> dict:
        import json
        try:
            with open(cls._resolve_path()) as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {}

    @classmethod
    def get(cls, key, default=None):
        return cls._read().get(key, default)

    @classmethod
    def set(cls, key, value):
        data = cls._read()
        data[key] = value
        try:
            _write_private_json(cls._resolve_path(), data)
        except Exception:
            pass
