#!/usr/bin/env python3
"""QuantaCrypt -- single binary entry point.

Launch behaviour:
  1. If this binary IS a .qcx file (self-executing payload appended) -> Decryptor
  2. If a .qcx path is passed as argv[1]                            -> Decryptor
  3. Otherwise                                                       -> Launcher
"""

import os
import sys
import threading

# When running as a frozen PyInstaller bundle, _MEIPASS is the temp dir
# containing unpacked resources.  Add it to sys.path so that bundled
# packages (quantacrypt, tkinterdnd2, etc.) are importable.
if getattr(sys, "frozen", False):
    _base = sys._MEIPASS          # type: ignore[attr-defined]
    sys.path.insert(0, _base)
else:
    _base = os.path.dirname(os.path.abspath(__file__))

# NOTE: we deliberately do NOT import quantacrypt.ui.decryptor at module top.
# That import transitively pulls in core.crypto (argon2, kyber_py, cryptography),
# ~200–400 ms of startup cost on macOS.  The common path — user launches the
# app to open the launcher — never needs the decryptor.  Defer to the branches
# that actually use it.

# Apple Events can fire concurrently if the user drops multiple files on the
# dock icon in quick succession.  Without a lock, two invocations can each
# create wizards that race on the same underlying file.  The lock makes each
# event handle its paths to completion before the next one starts.
_open_document_lock = threading.Lock()

# .qcx magic bytes — inlined so we can detect self-executing payloads
# without importing core.crypto at startup.  Keep in sync with
# quantacrypt.core.crypto.MAGIC.
_QCX_MAGIC = b"QCBIN\x01"
_QCX_TAIL_SCAN = 1 << 20  # 1 MB window at the end of the file


def _binary_has_qcx_payload(path: str) -> bool:
    """Cheap magic-bytes probe: does *path* look like a self-executing .qcx?

    We only need to decide whether to import the heavyweight decryptor stack;
    the full parse happens inside load_pkg() once we know it's worth it.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    tail = min(size, _QCX_TAIL_SCAN)
    try:
        with open(path, "rb") as f:
            f.seek(size - tail)
            buf = f.read(tail)
    except OSError:
        return False
    return _QCX_MAGIC in buf


def _register_open_document(root):
    """Register a macOS Apple Event handler for opening .qcx/.qcv files.

    When a user double-clicks a .qcx or .qcv file while the app is already
    running, macOS sends an ``kAEOpenDocuments`` event.  Tk on macOS exposes
    this via the ``::tk::mac::OpenDocument`` Tcl command.  We register a
    callback so those files are routed to the appropriate screen automatically.
    """
    def _open_document(*paths):
        # Serialize handler invocations so multiple files dropped on the
        # dock icon don't spawn racing wizards.
        with _open_document_lock:
            for path in paths:
                if not os.path.isfile(path):
                    continue
                # .qcv → Volume Manager (mount mode)
                if path.lower().endswith(".qcv"):
                    try:
                        from quantacrypt.ui.volume_manager import VolumeManagerApp
                        VolumeManagerApp(root, volume_path=path)
                    except Exception:
                        # Swallow import/ctor errors so the Apple Event loop
                        # doesn't wedge; the user can retry via the launcher.
                        pass
                    continue
                # .qcx → Decryptor (lazy import: first Apple Event pays the
                # crypto-stack import cost; subsequent events are free).
                try:
                    from quantacrypt.ui.decryptor import load_pkg, DecryptorApp
                    pkg = load_pkg(path)
                except (ValueError, OSError):
                    continue
                # Provide on_close so closing this window doesn't leave
                # the app running with no visible windows
                try:
                    DecryptorApp(root, payload=pkg, qcx_path=path,
                                 on_close=lambda: None)
                except Exception:
                    pass

    try:
        root.createcommand("::tk::mac::OpenDocument", _open_document)
    except Exception:
        # Not on macOS or Tcl/Tk doesn't support it — no-op
        pass


def _register_quit(root, launcher=None):
    """Route the Quit Apple event (app menu, Dock, ⌘Q) through the same
    guard as the launcher's close button.

    Tk Aqua evaluates ``::tk::mac::Quit`` when the command exists and plain
    ``exit`` otherwise — which raises SystemExit into mainloop() with no
    mounted-volume dialog, no unmount and no clipboard wipe (run 18 F-205).
    Every open wizard is asked first through its ``can_quit()`` (run 19
    F-001): freshly generated shares are the only way to open the file
    just written.
    """
    def _quit():
        from quantacrypt.ui.shared import ClipboardTimer
        # The wizards first — their can_quit() is a pure predicate that
        # changes no state, so no later veto can strand a job an earlier
        # window already cancelled (review run 20 F-005).  A window that
        # cannot answer — mid destroy — is not a veto.  The launcher is
        # evaluated LAST: its can_quit() unmounts (and can veto if that
        # fails), which must not run until every wizard has consented
        # (review run 21 F-002).
        wizards = [w for w in root.winfo_children() if w is not launcher]
        for win in wizards:
            guard = getattr(win, "can_quit", None)
            if guard is None:
                continue
            try:
                if not guard():
                    return
            except Exception:
                continue
        if launcher is not None:
            try:
                alive = launcher.winfo_exists()
            except Exception:
                alive = False
            if alive:
                try:
                    if not launcher.can_quit():          # prompts + unmounts; may veto
                        return
                except Exception:
                    pass
        # Committed: run each wizard's deferred teardown, then wipe + destroy.
        for win in wizards:
            commit = getattr(win, "commit_quit", None)
            if commit is not None:
                try:
                    commit()
                except Exception:
                    pass
        ClipboardTimer.wipe_all()
        root.destroy()

    try:
        root.createcommand("::tk::mac::Quit", _quit)
    except Exception:
        # Not on macOS or Tcl/Tk doesn't support it — no-op
        pass


def _make_root():
    """Create a single persistent hidden Tk root shared by all screens.

    Using one root avoids the Python 3.13 macOS bug where destroying a Tk
    instance and then creating a new one corrupts the Tcl interpreter
    (TclError: invalid command name).  All app windows are Toplevels on
    this root; the root itself is never shown directly.
    """
    try:
        from tkinterdnd2 import TkinterDnD
        root = TkinterDnD.Tk()
    except ImportError:
        import tkinter as tk
        root = tk.Tk()
    root.withdraw()

    # Set the app icon (replaces the default Python rocket in the dock)
    try:
        import tkinter as tk
        _assets = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "assets",
        )
        if getattr(sys, "frozen", False):
            icon_path = os.path.join(_base, "icon.png")
        else:
            icon_path = os.path.join(_assets, "icon.png")
        if os.path.isfile(icon_path):
            img = tk.PhotoImage(file=icon_path)
            root.iconphoto(True, img)
            root._icon_img = img  # prevent GC from collecting it
    except (tk.TclError, OSError):
        pass

    return root


def main():
    """Determine launch mode and start the appropriate screen."""
    root = _make_root()
    _register_open_document(root)

    # Case 1: self-executing .qcx (binary with payload appended).
    # Do a cheap magic-bytes probe first so the common (non-self-payload)
    # binary doesn't pay the cost of importing the decryptor stack here.
    exe = sys.executable if getattr(sys, "frozen", False) else __file__
    if _binary_has_qcx_payload(exe):
        from quantacrypt.ui.decryptor import load_pkg, DecryptorApp
        try:
            self_payload = load_pkg(exe)
        except (ValueError, OSError):
            self_payload = None
        if self_payload:
            DecryptorApp(root, payload=self_payload, qcx_path=exe)
            _register_quit(root)
            root.mainloop()
            return

    # Case 2: .qcx path passed as argument
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if os.path.isfile(arg):
            # Case 2a: .qcv volume → open Volume Manager in mount mode
            if arg.lower().endswith(".qcv"):
                from quantacrypt.ui.launcher import LauncherApp
                launcher = LauncherApp(root)
                _register_quit(root, launcher)
                # Defer volume open until after mainloop starts.  Wrap in a
                # try/except so that a failed import or constructor (e.g.
                # missing fusepy) doesn't leave the launcher withdrawn with
                # no visible window — the user sees an error dialog instead.
                def _deferred_open():
                    try:
                        launcher._open_volumes(volume_path=arg)
                    except Exception as exc:
                        from tkinter import messagebox
                        from quantacrypt.ui.shared import friendly_error
                        try:
                            launcher.deiconify()
                        except Exception:
                            pass
                        messagebox.showerror(
                            "Cannot open volume",
                            f"{os.path.basename(arg)}\n\n{friendly_error(exc)}",
                            parent=launcher,
                        )
                root.after(100, _deferred_open)
                root.mainloop()
                return

            # Case 2b: .qcx encrypted file → Decryptor
            from quantacrypt.ui.decryptor import load_pkg, DecryptorApp
            try:
                pkg = load_pkg(arg)
            except Exception as e:  # noqa: BLE001 — a hostile file must get the dialog, never a traceback
                from tkinter import messagebox
                from quantacrypt.ui.shared import friendly_error
                messagebox.showerror(
                    "Cannot open file",
                    f"{os.path.basename(arg)}\n\n{friendly_error(e)}",
                    parent=root,
                )
                root.destroy()
                return
            DecryptorApp(root, payload=pkg, qcx_path=arg)
            _register_quit(root)
            root.mainloop()
            return

    # Case 3: Launcher
    from quantacrypt.ui.launcher import LauncherApp
    launcher = LauncherApp(root)
    _register_quit(root, launcher)
    root.mainloop()


if __name__ == "__main__":
    main()
