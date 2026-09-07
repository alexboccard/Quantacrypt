"""FUSE filesystem for mounting QuantaCrypt encrypted volumes (.qcv).

Requires a FUSE backend — FUSE-T or macFUSE on macOS, libfuse on Linux — and
the ``fusepy`` Python package.
Install a backend: brew install --cask fuse-t   (recommended; or macfuse)
Install fusepy:    pip install fusepy

Usage (programmatic):
    from quantacrypt.core.fuse_ops import mount_volume, unmount_volume
    mount_volume("/path/to/vault.qcv", final_key, "/Volumes/MyVault")

The module exposes a QuantaCryptFUSE class implementing fusepy's Operations
interface. All filesystem operations decrypt/encrypt on-the-fly through a
VolumeContainer instance from volume.py.
"""

from __future__ import annotations

import atexit
import errno
import hashlib
import logging
import math
import os
import re
import signal
import stat
import sys
import threading
import time
from collections import OrderedDict
from typing import Any

logger = logging.getLogger(__name__)

#: The install commands every "no FUSE backend" message names (the Tk
#: guided-setup screen imports these; the Swift shell carries its own copy).
FUSE_INSTALL_CMD = "brew install --cask fuse-t"
FUSE_INSTALL_ALT = "brew install --cask macfuse"
FUSE_INSTALL_HINT = f"  macOS: {FUSE_INSTALL_CMD}   (recommended; or {FUSE_INSTALL_ALT})\n"

#: libfuse's hide-rename target: exactly this shape, and only for a file
#: that has an fd open (`hide_node` is gated on `is_open`).
_HIDDEN_RE = re.compile(r"\.fuse_hidden[0-9a-f]{16}")

from quantacrypt.core.errors import InvalidInput, safe_reason
from quantacrypt.core.volume import VOLUME_CHUNK_SIZE, VolumeContainer, _typed_mode


# ── FUSE availability check ─────────────────────────────────────────────────

#: Where a FUSE backend's libfuse legitimately lives on macOS.
_FUSE_LIBRARY_ROOTS = ("/usr/local/lib", "/opt/homebrew/lib",
                       "/Library/Frameworks", "/Library/Filesystems")


def _prepare_fuse_environment() -> None:
    """Point fusepy at FUSE-T's libfuse when nothing else would be found.

    fusepy's Darwin loader resolves the library via find_library('fuse')
    or the FUSE_LIBRARY_PATH env var — it never looks for
    ``libfuse-t.dylib``, so a FUSE-T-only machine (our recommended
    install) would fail with "Unable to find libfuse" despite having a
    working backend.  macFUSE registers itself with find_library, so we
    only intervene when it is absent.
    """
    import sys
    if sys.platform != "darwin":
        return
    preset = os.environ.get("FUSE_LIBRARY_PATH")
    if preset:
        # fusepy hands this straight to ctypes.CDLL, in the process that
        # holds every mounted volume's key.  A same-user process that can
        # shape this app's environment (launchctl setenv, a LaunchAgent)
        # would otherwise choose the library.  Honour it only when it names
        # a file under one of the places a FUSE backend is installed.
        if any(os.path.realpath(preset).startswith(root + os.sep)
               for root in _FUSE_LIBRARY_ROOTS) and os.path.isfile(preset):
            return
        logger.warning("Ignoring FUSE_LIBRARY_PATH=%r: not a FUSE backend location", preset)
        del os.environ["FUSE_LIBRARY_PATH"]
    if os.path.isdir("/Library/Filesystems/macfuse.fs"):
        return
    for cand in ("/opt/homebrew/lib/libfuse-t.dylib",
                 "/usr/local/lib/libfuse-t.dylib"):
        if os.path.isfile(cand):
            os.environ["FUSE_LIBRARY_PATH"] = cand
            return


def check_fuse_available() -> tuple[bool, str]:
    """Check whether fusepy and a FUSE backend are available.

    Returns (available, message).

    fusepy raises ImportError when the package is missing but
    EnvironmentError (an OSError) when the package imports and no libfuse
    backend can be loaded — both must be caught or the "helpful error"
    path itself crashes on machines without a backend.
    """
    try:
        _prepare_fuse_environment()
        import fuse  # noqa: F401
        return True, "fusepy is available"
    except ImportError:
        return False, (
            "fusepy is not installed. Install it with:\n"
            "  pip install fusepy\n\n"
            "You also need a FUSE backend:\n"
            + FUSE_INSTALL_HINT +
            "  Linux: sudo apt install libfuse-dev"
        )
    except OSError as exc:
        return False, (
            f"fusepy is installed but could not load a FUSE backend ({exc}).\n\n"
            "Install a backend:\n"
            + FUSE_INSTALL_HINT +
            "  Linux: sudo apt install libfuse-dev"
        )


def check_fuse_components() -> dict[str, dict[str, Any]]:
    """Return per-component availability for FUSE setup.

    Returns a dict with keys ``fusepy`` and ``fuse_backend``, each containing:
      - ``ok``      (bool): True if the component is available
      - ``detail``  (str):  Human-readable status message
    """
    import shutil
    import sys

    result: dict[str, dict[str, Any]] = {}

    # 1. fusepy Python package (OSError = installed but backend unloadable;
    # see check_fuse_available)
    try:
        _prepare_fuse_environment()
        import fuse  # noqa: F401
        result["fusepy"] = {"ok": True, "detail": "fusepy is installed"}
    except ImportError:
        result["fusepy"] = {"ok": False, "detail": "fusepy is not installed"}
    except OSError as exc:
        result["fusepy"] = {
            "ok": False,
            "detail": f"fusepy cannot load a FUSE backend: {exc}",
        }

    # 2. System FUSE backend
    if sys.platform == "darwin":
        # Check for FUSE-T or macFUSE.  Homebrew installs to /opt/homebrew
        # on Apple Silicon (M1+) and /usr/local on Intel; check both.
        has_fuse_t = (
            os.path.isfile("/opt/homebrew/lib/libfuse-t.dylib")
            or os.path.isfile("/usr/local/lib/libfuse-t.dylib")
        )
        has_macfuse = os.path.isdir("/Library/Filesystems/macfuse.fs")
        has_osxfuse = os.path.isdir("/Library/Filesystems/osxfuse.fs")
        if has_fuse_t:
            result["fuse_backend"] = {"ok": True, "detail": "FUSE-T detected"}
        elif has_macfuse:
            result["fuse_backend"] = {"ok": True, "detail": "macFUSE detected"}
        elif has_osxfuse:
            result["fuse_backend"] = {"ok": True, "detail": "osxfuse detected"}
        else:
            result["fuse_backend"] = {
                "ok": False,
                "detail": "No FUSE backend found (macFUSE or FUSE-T)",
            }
    else:
        # Linux: check for fusermount or /dev/fuse
        has_fusermount = shutil.which("fusermount") is not None
        has_fusermount3 = shutil.which("fusermount3") is not None
        has_dev_fuse = os.path.exists("/dev/fuse")
        if has_fusermount or has_fusermount3 or has_dev_fuse:
            result["fuse_backend"] = {"ok": True, "detail": "FUSE detected"}
        else:
            result["fuse_backend"] = {
                "ok": False,
                "detail": "No FUSE backend found (libfuse)",
            }

    return result


# ── LRU Cache ───────────────────────────────────────────────────────────────

class LRUCache:
    """Simple LRU cache with max size in bytes."""

    def __init__(self, max_bytes: int = 100 * 1024 * 1024):
        self._cache: OrderedDict[str, bytes] = OrderedDict()
        self._sizes: dict[str, int] = {}
        self._current_bytes = 0
        self._max_bytes = max_bytes

    def get(self, key: str) -> bytes | None:
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def put(self, key: str, data: bytes) -> None:
        if key in self._cache:
            self._current_bytes -= self._sizes.pop(key)
            del self._cache[key]
        if len(data) > self._max_bytes:
            # It could never stay: inserting it would evict every other
            # entry and then itself.
            return

        self._cache[key] = data
        self._sizes[key] = len(data)
        self._current_bytes += len(data)
        self._cache.move_to_end(key)

        # Evict oldest entries if over limit
        while self._current_bytes > self._max_bytes and self._cache:
            oldest_key, _ = self._cache.popitem(last=False)
            self._current_bytes -= self._sizes.pop(oldest_key, 0)

    def invalidate(self, key: str) -> None:
        if key in self._cache:
            self._current_bytes -= self._sizes.pop(key, 0)
            del self._cache[key]

    def invalidate_prefix(self, prefix: str) -> None:
        """Drop every entry whose key starts with ``prefix`` (dir renames)."""
        for key in [k for k in self._cache if k.startswith(prefix)]:
            self._current_bytes -= self._sizes.pop(key, 0)
            del self._cache[key]

    def clear(self) -> None:
        self._cache.clear()
        self._sizes.clear()
        self._current_bytes = 0

    @property
    def size(self) -> int:
        return self._current_bytes

    def __len__(self) -> int:
        return len(self._cache)


# ── FUSE Operations ─────────────────────────────────────────────────────────

# fusepy dispatches every kernel op by CALLING the operations object —
# self.operations('getattr', path, fh) — a protocol only fuse.Operations
# provides via __call__ (plus sane defaults for the ~20 ops we don't
# implement).  Subclassing it is therefore mandatory for a real mount to
# work; a plain class "mounts" fine and then fails every op with EINVAL.
# The import is guarded so this module (and the direct-call test suite)
# stays importable when fusepy is absent — mount_volume() re-checks
# availability before any real mount.
# OSError too: fusepy raises EnvironmentError at import time when no
# libfuse backend loads — the module must stay importable on such machines
# so check_fuse_components can show the guided-setup screen.
try:
    _prepare_fuse_environment()
    from fuse import Operations as _FuseOperations
except (ImportError, OSError):  # pragma: no cover — dev/CI installs fusepy
    class _FuseOperations:
        """Stand-in base so the module imports without fusepy/libfuse."""


class QuantaCryptFUSE(_FuseOperations):
    """FUSE filesystem backed by an encrypted .qcv volume.

    Implements the fusepy Operations interface. All methods translate
    POSIX filesystem calls into VolumeContainer operations with
    on-the-fly encryption/decryption.
    """

    #: libfuse may call fd-based operations on a node it can no longer name
    #: (an open file under a directory whose rmdir succeeded).  Without this
    #: flag it answers ENOENT itself for read/write/fsync/fstat and never
    #: calls us; with it, the path arrives as NULL and the fd is the
    #: identity (_fh_vpath).  fusepy copies the flag into fuse_operations.
    flag_nullpath_ok = 1

    def __init__(self, volume: VolumeContainer, cache_mb: int = 100):
        self.volume = volume
        self.cache = LRUCache(max_bytes=cache_mb * 1024 * 1024)
        # vpath → {"mode": …, "mtime": …} set by chmod/utimens while the
        # file's data was still buffered.  cp -p and ditto stamp *before*
        # closing (rsync, tar and unzip after — those hit the not-dirty
        # path), and the flush that release() runs would otherwise rebuild
        # the entry with the copy time (seen live).  Kept ONLY here — not in
        # the index — so getattr overlays it and a later write() reverting
        # the mtime also reverts what the caller sees; the flush's single
        # write record (or, for unchanged bytes, one setattr record)
        # carries it.  Per-path state like the buffers: mtime cleared by
        # write()/truncate() (a modification), all of it consumed by
        # flush()/release()/save_all_dirty(), dropped on unlink and for a
        # replaced rename destination, re-keyed by rename.
        self._deferred_attrs: dict[str, dict[str, Any]] = {}
        # `.fuse_hidden*` names libfuse renamed unlinked-but-open files to in
        # THIS session (see rename).  Only these are litter the shutdown
        # sweep may delete; a user's file that happens to carry the prefix,
        # or litter inherited from a crashed session, is not ours to remove.
        self._hidden_seen: set[str] = set()
        # The mount root has no index entry.  rsync -a and cp -Rp set the
        # destination root's times and mode after the transfer, and ENOENT
        # there failed every scripted backup after copying everything.
        # Kept in memory: a remount's root is as new as the mount.
        self._root_mode = stat.S_IFDIR | 0o755
        self._root_mtime = time.time()
        # RLock, not Lock: SIGTERM/SIGINT handlers run _emergency_save_all
        # on the main thread; if the signal lands while the main thread is
        # already inside save_all_dirty (e.g. via unmount_volume), a plain
        # Lock would self-deadlock and no volume would get its emergency
        # save.
        self._lock = threading.RLock()
        self._fd_counter = 0
        self._open_files: dict[int, str] = {}  # fd → vpath
        self._dirty_files: set[str] = set()
        self._file_buffers: dict[str, bytearray] = {}
        # POSIX unlink-while-open semantics: if a path is unlinked while an
        # fd is still open, the dir_index entry sticks around and the data
        # stays readable via that fd until the last close.  This set tracks
        # paths in that limbo state; release() performs the real delete
        # when the last fd closes.
        self._pending_unlink: set[str] = set()

    def _vpath(self, path: str) -> str:
        """Normalize FUSE path to volume path format."""
        if not path.startswith("/"):
            path = "/" + path
        return path

    def _fh_vpath(self, path: str | None, fh: int | None) -> str:
        """The vpath of an fd-based operation.

        libfuse passes a NULL path (fusepy: ``None``) when it can no longer
        name the open node — a file it renamed to ``.fuse_hidden*`` under a
        directory that is gone, for one — so the fd, not the path, is the
        identity here.  Raising from ``None.startswith`` turned the close of
        such a file into EINVAL and lost its last writes.
        """
        # The fd first whenever it is one of ours: rename keeps _open_files
        # current, and libfuse's release() passes the placeholder "-" (not
        # NULL) for a node it cannot name, which would otherwise become the
        # vpath "/-" and leave the real file's buffer behind.
        if fh is not None:
            vpath = self._open_files.get(fh)
            if vpath is not None:
                return vpath
        if path is not None and path != "-":
            return self._vpath(path)
        raise OSError(errno.EBADF, "Bad file descriptor")


    def _dir_vpath(self, path: str) -> str:
        """Normalize path as a directory key (trailing slash)."""
        vp = self._vpath(path)
        if vp != "/" and not vp.endswith("/"):
            vp += "/"
        return vp

    def _next_fd(self) -> int:
        self._fd_counter += 1
        return self._fd_counter

    def __call__(self, op: str, *args):
        """fusepy's dispatch, with the uncaught-exception report made safe.

        fusepy logs an exception that escapes an operation at ERROR with the
        traceback, and its cause line names a vault path more often than not
        (volume.py embeds the vpath in its messages).  ERROR is public in the
        shell's unified log, so the operation and the exception type go
        there, the traceback rides a private INFO line, and the kernel gets
        the EINVAL fusepy would have answered.  OSError is the ordinary
        errno path and passes through untouched.
        """
        if not hasattr(self, op):
            raise OSError(errno.EFAULT, "Bad address")
        try:
            return getattr(self, op)(*args)
        except OSError as exc:
            if not exc.errno or exc.errno < 0:
                # fusepy compares `errno > 0`: None makes its wrapper raise
                # NameError out of the ctypes callback (the kernel is told
                # the op succeeded); zero or negative takes its "negative
                # errno" branch — an ERROR traceback, public line by line,
                # cause included.  Nothing here builds one, but the
                # contract must not depend on that.
                logger.error("FUSE operation %s failed: %s; returning EIO",
                             op, safe_reason(exc))
                logger.info("FUSE operation %s failed", op, exc_info=True)
                raise OSError(errno.EIO, "Input/output error") from exc
            raise
        except Exception as exc:  # noqa: BLE001 — reported, then EINVAL
            logger.error("FUSE operation %s failed: %s; returning EINVAL",
                         op, safe_reason(exc))
            logger.info("FUSE operation %s failed", op, exc_info=True)
            raise OSError(errno.EINVAL, "Invalid argument") from exc

    def _writable(self, path: str) -> None:
        """Refuse a mutation on a read-only mount before any state changes.

        The kernel enforces ``-o ro`` for real mounts; this is the same
        answer for callers that reach the operations directly, and it
        keeps the namespace free of entries the container can never hold.
        """
        if self.volume.read_only:
            raise OSError(errno.EROFS, "Read-only file system", path)

    def _defer(self, vpath: str, **attrs: Any) -> None:
        self._deferred_attrs.setdefault(vpath, {}).update(attrs)

    def _undefer_mtime(self, vpath: str) -> None:
        """A data write is a modification: the flush stamps now(), but a
        deferred chmod still stands."""
        d = self._deferred_attrs.get(vpath)
        if d is not None:
            d.pop("mtime", None)
            if not d:
                del self._deferred_attrs[vpath]

    def _write_back(self, vpath: str, snapshot: bytes, attrs: dict[str, Any]) -> None:
        """Persist a dirty buffer.  Caller holds ``_lock``.

        A write that leaves the bytes identical to what the container holds
        (editors re-saving unchanged files, periodic fsync from rsync and
        databases, a size-preserving ftruncate) must not re-encrypt and
        append the whole file again; then only the attributes deferred to
        this flush are journaled.  One place for flush(), release() and
        save_all_dirty(), which used to disagree.
        """
        entry = self.volume.get_entry(vpath)
        unchanged = (
            entry is not None
            and entry.get("type") != "dir"
            and entry.get("size") == len(snapshot)
            and entry.get("content_hash")
            and entry["content_hash"] == hashlib.sha256(snapshot).hexdigest()
        )
        if not unchanged:
            self.volume.write_file(vpath, snapshot, mtime=attrs.get("mtime"),
                                   mode=attrs.get("mode"))
            # Chunks cached from the previous content are stale now.
            self._invalidate_cached(vpath)
        elif attrs:
            self.volume.set_attrs(vpath, **attrs)

    # ── Filesystem info ─────────────────────────────────────────────────

    def statfs(self, path: str) -> dict:
        """Return filesystem statistics.

        Free space is the HOST filesystem's: the container grows on the
        host disk, so that is the true bound on what can still be
        written (the approach gocryptfs/Cryptomator take).  The old
        ``max(container, 1 GB) − plaintext`` formula collapsed to ~zero
        free once a volume held ≈1 GB — Finder's free-space pre-flight
        then refused every copy into the mount — and journal dead space
        inflated the number after deletes.
        """
        with self._lock:
            stats = self.volume.stat()
        used = stats.get("total_plaintext_size", 0)
        bsize = 4096
        try:
            host = os.statvfs(
                os.path.dirname(os.path.abspath(self.volume.path)) or "/")
            host_free = host.f_bavail * host.f_frsize
        except OSError:
            host_free = 1 << 40  # host unstat-able: claim 1 TB free
        # NB: the write path's memory ceiling is deliberately NOT applied
        # here. It bounds a single file, not the filesystem, and folding it
        # into f_bavail made a volume on a 274 GB disk report 2 GB total and
        # 2 GB free — a worse lie than the one it set out to fix, and a
        # return of the very "full disk" symptom R8 F-001 removed. The bound
        # is enforced in write(), where it actually applies, as EFBIG.
        total_blocks = (used + host_free) // bsize
        free_blocks = host_free // bsize
        return {
            "f_bsize": bsize,
            "f_frsize": bsize,
            "f_blocks": total_blocks,
            "f_bfree": free_blocks,
            "f_bavail": free_blocks,
            "f_files": stats.get("file_count", 0) + stats.get("dir_count", 0),
            "f_ffree": 1000000,
            "f_favail": 1000000,
            "f_namemax": 255,
        }

    # ── Attributes ──────────────────────────────────────────────────────

    def getattr(self, path: str, fh: int | None = None) -> dict:
        """Return file/directory attributes (stat)."""
        by_fd = fh is not None and fh in self._open_files
        vpath = self._fh_vpath(path, fh)

        # Root directory
        if vpath == "/":
            return {
                "st_mode": self._root_mode,
                "st_nlink": 2,
                "st_size": 0,
                "st_uid": os.getuid(),
                "st_gid": os.getgid(),
                "st_atime": self._root_mtime,
                "st_mtime": self._root_mtime,
                "st_ctime": self._root_mtime,
            }

        # POSIX: once a file has been unlinked, the pathname is no longer
        # resolvable even if fds remain open on it.  The still-open fd can
        # access data via its fh (FUSE read/write), but a fresh getattr
        # against the name must fail.
        # One acquisition for the whole read: the unlink set, the index
        # lookup and the buffer size are all mutated by other FUSE workers,
        # and a torn read across them reports a size for a file that is no
        # longer there. _lock is an RLock, so nesting inside callers is free.
        with self._lock:
            # By name an unlinked-but-open file is gone; by fd (fstat) it is
            # still there.
            if not by_fd and vpath in self._pending_unlink:
                raise OSError(errno.ENOENT, "No such file or directory", path)

            # Check as file first, then as directory
            entry = self.volume.get_entry(vpath)
            if entry is None:
                entry = self.volume.get_entry(vpath + "/")
            if entry is None:
                raise OSError(errno.ENOENT, "No such file or directory", path)

            is_dir = entry.get("type") == "dir"
            mode = entry.get("mode", 0o40755 if is_dir else 0o100644)
            mtime = entry.get("mtime", int(time.time()))
            deferred = self._deferred_attrs.get(vpath)
            if deferred:
                if "mode" in deferred:
                    mode = _typed_mode(entry, deferred["mode"])
                mtime = deferred.get("mtime", mtime)

            # If the file has been modified in a buffer, report buffer size
            size = entry.get("size", 0)
            if vpath in self._file_buffers:
                size = len(self._file_buffers[vpath])

        return {
            "st_mode": mode,
            "st_nlink": 2 if is_dir else 1,
            "st_size": size,
            "st_uid": os.getuid(),
            "st_gid": os.getgid(),
            "st_atime": mtime,
            "st_mtime": mtime,
            "st_ctime": mtime,
        }

    # ── Directory operations ────────────────────────────────────────────

    def readdir(self, path: str, fh: int | None = None) -> list[str]:
        """List directory contents.

        Filters out paths that have been unlinked-with-fds-still-open —
        POSIX says they must not show up in the namespace, even though
        dir_index still carries the entry until the last close.
        """
        if path is None:
            # No directory fh is tracked (opendir is the default no-op), so
            # a directory libfuse cannot name is one whose rmdir succeeded.
            raise OSError(errno.ENOENT, "No such file or directory")
        vpath = self._vpath(path)
        entries = [".", ".."]
        with self._lock:
            # Both reads under one acquisition: list_dir() walks dir_index,
            # which other FUSE workers mutate.
            raw = self.volume.list_dir(vpath)
            pending = set(self._pending_unlink)
        if pending:
            prefix = vpath if vpath.endswith("/") else vpath + "/"
            if vpath == "/":
                prefix = "/"
            raw = [n for n in raw if (prefix + n) not in pending]
        entries.extend(raw)
        return entries

    def mkdir(self, path: str, mode: int) -> None:
        """Create a directory with the kernel's (umask-applied) mode."""
        self._writable(path)
        with self._lock:
            self.volume.mkdir(self._dir_vpath(path), mode=mode)
            self._persist_locked()

    def rmdir(self, path: str) -> None:
        """Remove an empty directory.

        A directory holding an unlinked-but-open file (kept in the index
        until its last close; libfuse renames it to `.fuse_hidden*`) is NOT
        removable, and deliberately so: `rm -rf` of it fails with ENOTEMPTY
        where APFS would succeed, but the alternative was tried (runs 15–16)
        and the macFUSE kernel revokes the open child's descriptors the
        moment an rmdir succeeds — every later write on that fd fails with
        ENXIO and the app's unsaved data is lost.  A visible, retryable
        error beats that.  Litter from a crashed session is an ordinary
        entry: `rm -rf` unlinks it first.
        """
        self._writable(path)
        with self._lock:
            dir_vp = self._dir_vpath(path)
            children = self.volume.list_dir(dir_vp.rstrip("/"))
            if children:
                raise OSError(errno.ENOTEMPTY, "Directory not empty", path)
            self.volume.delete(dir_vp)
            self._persist_locked()

    def _persist_locked(self) -> None:
        """Persist volume state if dirty.  Caller must hold ``_lock``.

        save() is a journal append — O(size of the change) — so calling it
        on every metadata op and flush is cheap.  Deferring persistence to
        unmount (the pre-fix behavior) meant a crash, SIGKILL, or power
        loss silently discarded every write since mount.
        """
        if not self.volume.is_dirty:
            return
        if self.volume.read_only:
            # Already flipped: nothing can be saved, and the ESTALE path
            # keeps memory dirty on purpose (no re-read of a foreign file),
            # so every later flush/release would otherwise re-log the
            # failure and re-hit the disk.  One report, then silence.
            return
        try:
            self.volume.save()
        except OSError as exc:
            if exc.errno == errno.ESTALE:
                # The file at the path is no longer the one this mount opened
                # (replaced, overwritten in place, moved, or removed).  Serve
                # what was opened, read-only, until unmount; the on-disk file
                # is foreign, so no re-read.  When the inode was orphaned,
                # its records exist only in the descriptor this mount holds —
                # rescue them to a sidecar before unmount frees it.
                self.volume.read_only = True
                sidecar = self.volume.rescue_if_orphaned()
                if sidecar:
                    logger.error("a mounted volume's container changed on disk "
                                 "beneath the mount; it is now read-only and the "
                                 "volume as this mount had it was preserved beside "
                                 "it (see the log for where)")
                else:
                    logger.error("a mounted volume's container changed on disk "
                                 "beneath the mount (moved, replaced, or "
                                 "overwritten); it is now read-only and this "
                                 "change was not saved")
                logger.info("container identity changed at %s: %s (%s)",
                            self.volume.path, exc,
                            f"preserved to {sidecar}" if sidecar else "not orphaned")
                raise
            if isinstance(exc, PermissionError) or exc.errno == errno.EROFS:
                # The layout stopped accepting writes after the mount
                # (write-protect switch, share re-exported read-only,
                # permissions tightened).  Memory is now ahead of disk for
                # this change; refuse every later mutation before it touches
                # state instead of failing each one after the fact.
                self.volume.read_only = True
                # ERROR is public in the shell's unified log (it must be:
                # it is the trace of why a mount went read-only); the
                # container path is not, so it rides a private INFO line.
                logger.error("a mounted volume stopped accepting writes; the "
                             "mount is now read-only and this change was not "
                             "saved: %s", safe_reason(exc))
                logger.info("read-only flip at %s", self.volume.path)
                # Memory would otherwise keep serving the refused change
                # (a phantom directory, new bytes that vanish at remount):
                # drop everything unsaved and re-read the index from disk.
                # A failure re-reading (read was revoked too) must not
                # replace the original error the caller is about to see.
                try:
                    self.volume.discard_unsaved()
                except Exception:  # noqa: BLE001 — the original exc wins
                    logger.info("could not re-read the index after the flip at %s",
                                self.volume.path, exc_info=True)
            raise

    # ── File operations ─────────────────────────────────────────────────

    def create(self, path: str, mode: int, fi: Any = None) -> int:
        """Create a new file and return a file descriptor.

        If the path is still in ``_pending_unlink`` (unlinked while other
        fds remain open), refuse with EEXIST: our buffers are vpath-keyed,
        so allowing the create would corrupt the old fds' view.  The POSIX-
        correct alternative (per-fd buffers as separate inodes) is a bigger
        refactor; for our use case (editor swap, tempfile) it's safer to
        ask the caller to wait for the old fds to close.
        """
        self._writable(path)
        vpath = self._vpath(path)
        with self._lock:
            if vpath in self._pending_unlink:
                raise OSError(
                    errno.EEXIST,
                    "Path was unlinked but still has open fds",
                    path,
                )
            self.volume.write_file(vpath, b"", mode=mode)
            self._file_buffers[vpath] = bytearray()
            self._deferred_attrs.pop(vpath, None)
            fd = self._next_fd()
            self._open_files[fd] = vpath
        return fd

    def _chunk_key(self, vpath: str, chunk_index: int) -> str:
        """LRU cache key for one decrypted chunk of *vpath*.

        NUL never appears in a validated vpath, so the key space can't
        collide with another path — and every chunk key of a path (or of
        a whole directory subtree) is droppable via invalidate_prefix.
        """
        return f"{vpath}\x00{chunk_index}"

    def _invalidate_cached(self, vpath: str) -> None:
        """Drop all cached decrypted chunks for *vpath*."""
        self.cache.invalidate_prefix(vpath + "\x00")

    def open(self, path: str, flags: int) -> int:
        """Open a file and return a file descriptor.

        Does NOT materialize the plaintext: reads decrypt only the chunks
        they touch (read_file_range), so opening a 500 MB file is O(1)
        instead of a multi-second stall.  The full buffer is created
        lazily by the first write()/truncate() on the file.
        """
        vpath = self._vpath(path)
        if flags & (os.O_WRONLY | os.O_RDWR):
            self._writable(path)
        # POSIX: after unlink(), the pathname is unusable even for new
        # opens — the existing fds keep their view of the inode via fh,
        # but a fresh open(path) must fail.  Without this guard a second
        # open() aliases the same vpath-keyed _file_buffers and the final
        # release() would discard the new fd's writes under volume.delete.
        with self._lock:
            if vpath in self._pending_unlink:
                raise OSError(errno.ENOENT, "No such file or directory", path)
        entry = self.volume.get_entry(vpath)
        if entry is None:
            raise OSError(errno.ENOENT, "No such file", path)

        fd = self._next_fd()
        with self._lock:
            self._open_files[fd] = vpath
        return fd

    def read(self, path: str, size: int, offset: int, fh: int) -> bytes:
        """Read data from a file.

        A live write buffer (file being modified, or freshly created) is
        authoritative.  Otherwise decrypt just the chunks covering the
        range, through a chunk-granular LRU cache — sequential readers and
        seek-happy tools (media players, archive listers) hit the cache
        for re-read chunks without ever materializing the whole file.
        Per-chunk AES-GCM tags + AAD authenticate everything returned
        (whole-file SHA-256 stays available via read_file(verify_hash=True)).
        """
        vpath = self._fh_vpath(path, fh)
        if offset < 0:
            raise OSError(errno.EINVAL, "Invalid argument", path)
        with self._lock:
            buf = self._file_buffers.get(vpath)
            if buf is not None:
                return bytes(buf[offset:offset + size])

            entry = self.volume.get_entry(vpath)
            if entry is None:
                raise OSError(errno.ENOENT, "No such file", path)
            fsize = entry.get("size", 0)
            if size <= 0 or offset >= fsize:
                return b""
            end = min(offset + size, fsize)
            chunk_size = self.volume.metadata.get(
                "chunk_size", VOLUME_CHUNK_SIZE)
            first = offset // chunk_size
            last = (end - 1) // chunk_size
            parts: list[bytes] = []
            for ci in range(first, last + 1):
                key = self._chunk_key(vpath, ci)
                data = self.cache.get(key)
                if data is None:
                    data = self.volume.read_file_range(
                        vpath, ci * chunk_size, chunk_size)
                    self.cache.put(key, data)
                parts.append(data)
            plain = b"".join(parts)
            rel = offset - first * chunk_size
            return plain[rel:rel + (end - offset)]

    def write(self, path: str, data: bytes, offset: int, fh: int) -> int:
        """Write data to a file."""
        self._writable(path)
        if offset < 0:
            raise OSError(errno.EINVAL, "Invalid argument", path)
        vpath = self._fh_vpath(path, fh)
        with self._lock:
            end = offset + len(data)
            # The write path holds roughly 4x the file in RAM (buffer,
            # bytes() snapshot, per-chunk ciphertext list, joined result), so
            # a large enough file dies with a MemoryError mid-write and
            # flush()'s journal append never happens. Refusing up front with
            # EFBIG is a real error the user's tools understand, and unlike a
            # statfs cap it does not misreport the size of the volume.
            # Checked before anything is decrypted so a refused write
            # retains nothing.  The durable fix is chunk-granular writes.
            ceiling = _max_writable_bytes()
            if end > ceiling:
                raise OSError(
                    errno.EFBIG,
                    f"File would exceed this volume's {ceiling // (1 << 20)} MB "
                    "single-file limit (the encrypt path buffers it in memory)",
                    path,
                )
            buf = self._file_buffers.get(vpath)
            if buf is None:
                # First write on an untouched file: open() no longer
                # eagerly decrypts, so materialize the existing plaintext
                # here — starting from an empty buffer would zero
                # everything outside this write's range.
                entry = self.volume.get_entry(vpath)
                if entry is not None and entry.get("type") != "dir":
                    buf = bytearray(
                        self.volume.read_file(vpath, verify_hash=False))
                else:
                    buf = bytearray()
                self._file_buffers[vpath] = buf

            # Extend buffer if writing past end
            if end > len(buf):
                buf.extend(b"\x00" * (end - len(buf)))
            buf[offset:end] = data
            self._dirty_files.add(vpath)
            self._undefer_mtime(vpath)
        return len(data)

    def truncate(self, path: str, length: int, fh: int | None = None) -> None:
        """Truncate or extend a file to the given length."""
        self._writable(path)
        if length < 0:
            raise OSError(errno.EINVAL, "Invalid argument", path)
        vpath = self._fh_vpath(path, fh)
        with self._lock:
            if fh is None and vpath in self._pending_unlink:
                raise OSError(errno.ENOENT, "No such file or directory", path)
            buf = self._file_buffers.get(vpath)
            if buf is None:
                entry = self.volume.get_entry(vpath)
                if entry is None or entry.get("type") == "dir":
                    raise OSError(errno.ENOENT, "No such file or directory", path)
                current = entry.get("size", 0)
            else:
                current = len(buf)
            if length == current:
                # POSIX marks mtime for update only when the size changes;
                # treating this as a modification dropped a deferred stamp
                # and re-encrypted identical bytes on close.
                return
            if length > current:
                # Same ceiling as write(): ftruncate is how preallocating
                # tools (truncate -s, mkfile -n, torrent clients, disk-image
                # tools) reserve space, and an unbounded zero-fill here
                # materialises the whole length in RAM in one object.
                # Checked before anything is decrypted, so a refused request
                # retains nothing.
                ceiling = _max_writable_bytes()
                if length > ceiling:
                    raise OSError(
                        errno.EFBIG,
                        f"File would exceed this volume's {ceiling // (1 << 20)} MB "
                        "single-file limit (the encrypt path buffers it in memory)",
                        path,
                    )
            if buf is None:
                # open(O_TRUNC) — every `> file`, cp over an existing file,
                # editor save — arrives as truncate(path, 0) with no fd.
                # Decrypting the whole file just to discard it was an
                # O(file) stall and an O(file) allocation the write ceiling
                # does not guard; read only what survives.
                if length <= 0:
                    buf = bytearray()
                elif length < current:
                    buf = bytearray(self.volume.read_file_range(vpath, 0, length))
                else:
                    # verify_hash=False on the hot path (see open()).
                    buf = bytearray(self.volume.read_file(vpath, verify_hash=False))
                self._file_buffers[vpath] = buf
            if length < len(buf):
                del buf[length:]
            elif length > len(buf):
                buf.extend(b"\x00" * (length - len(buf)))
            self._dirty_files.add(vpath)
            self._undefer_mtime(vpath)
        if fh is None:
            # Path-based truncate (no open fd): nothing will flush this
            # buffer later, so persist it now like a flush would — and
            # nothing will release it either, so drop the plaintext once it
            # is persisted (reads decrypt by range without it).
            try:
                self.flush(path, 0)
            finally:
                # Whatever the flush did (a flip to read-only included), a
                # buffer nobody can release must not stay ahead of disk.
                with self._lock:
                    if not any(v == vpath for v in self._open_files.values()):
                        self._file_buffers.pop(vpath, None)

    def flush(self, path: str, fh: int) -> None:
        """Flush dirty data to the volume container and persist to disk."""
        vpath = self._fh_vpath(path, fh)
        with self._lock:
            if vpath in self._dirty_files:
                # A file unlinked while still open — a direct caller's
                # pending unlink, or libfuse's `.fuse_hidden*` rename — is
                # doomed: encrypting and journaling its buffer at every
                # close only to tombstone it made the temp-file pattern
                # (create, unlink, write, close) cost an O(size) encrypt per
                # fsync and drive compaction.  Drop it here.
                doomed = vpath in self._pending_unlink or vpath in self._hidden_seen
                if doomed:
                    # Skip the write, but forget nothing: the buffer, the
                    # dirty flag and the deferred attributes stay with the
                    # file.  A hidden file fsynced and then renamed back
                    # over a real name (the rescue the run-18 model fuzz
                    # reproduced 3/200) must still find content to persist
                    # at release(); dropping the flag here lost the whole
                    # file.  release() is where a still-doomed file is
                    # finally let go.  (On libfuse the node stays hidden
                    # through such a rename and is unlinked after the last
                    # close regardless — observed on macFUSE 5.1.3, see
                    # encrypted-volumes.md — so there the rescue is undone
                    # by the backend, not by a lost write-back.)
                    pass
                else:
                    if self.volume.read_only:
                        # The mount lost writability after this file was
                        # dirtied: say so at close(2) instead of letting
                        # memory move ahead of a disk that will never
                        # take it.
                        raise OSError(errno.EROFS, "Read-only file system", path)
                    # The attributes deferred to this flush belong to it;
                    # left in the map they would be applied to unrelated
                    # content renamed over this name later.
                    attrs = self._deferred_attrs.pop(vpath, None) or {}
                    buf = self._file_buffers.get(vpath, bytearray())
                    self._write_back(vpath, bytes(buf), attrs)
                    self._dirty_files.discard(vpath)
            self._persist_locked()

    def fsync(self, path: str, datasync: int, fh: int) -> int:
        """Force file data to stable storage (flush + journal append)."""
        self.flush(path, fh)
        return 0

    def release(self, path: str, fh: int) -> None:
        """Close a file descriptor."""
        vpath = self._fh_vpath(path, fh)
        with self._lock:
            # Flush if dirty (but skip the persist for unlink-while-open;
            # see flush() for why).
            if vpath in self._dirty_files:
                doomed = vpath in self._pending_unlink or vpath in self._hidden_seen
                if doomed:
                    pass                          # see flush(); dropped below
                elif self.volume.read_only:
                    # The name stays out of WARNING: the Swift shell mirrors
                    # helper stderr into the unified log, and vault-internal
                    # names are part of what the volume encrypts.
                    logger.warning("unsaved changes to one file dropped — "
                                   "the mount became read-only")
                    logger.debug("dropped unsaved buffer: %s", vpath)
                    self._dirty_files.discard(vpath)
                else:
                    attrs = self._deferred_attrs.pop(vpath, None) or {}
                    buf = self._file_buffers.get(vpath, bytearray())
                    self._write_back(vpath, bytes(buf), attrs)
                    self._dirty_files.discard(vpath)

            self._open_files.pop(fh, None)

            # Keep buffer in cache but remove from active buffers
            # if no other FDs have it open.  A doomed file's dirty flag
            # goes with the last descriptor — until then a rescue rename
            # through another fd can still claim the content.
            still_open = any(
                v == vpath for v in self._open_files.values()
            )
            if not still_open:
                self._file_buffers.pop(vpath, None)
                self._deferred_attrs.pop(vpath, None)
                self._dirty_files.discard(vpath)
                # If the last open fd for a deferred-unlink path just
                # closed, perform the real delete now.
                if vpath in self._pending_unlink:
                    self._pending_unlink.discard(vpath)
                    # Apply the delete even on a flipped mount: it only
                    # mutates memory (_persist_locked returns before saving
                    # a read-only volume), and skipping it made an
                    # acknowledged unlink reappear in the live namespace at
                    # the last close (review run 20 F-003).
                    try:
                        self.volume.delete(vpath)
                    except FileNotFoundError:
                        pass
                    self._invalidate_cached(vpath)
                    self._dirty_files.discard(vpath)
            self._persist_locked()

    def unlink(self, path: str) -> None:
        """Delete a file.

        POSIX requires that an unlinked file remain accessible through any
        still-open file descriptor until the last close ("delete on last
        close").  Many editors and tools rely on this — they create a
        temp file, unlink it immediately, then continue writing to the
        fd to get automatic cleanup on crash.  If we eagerly delete on
        every unlink we'd break that pattern AND (worse) silently
        resurrect the file on the next release() when the still-open fd
        flushes its buffer.
        """
        self._writable(path)
        vpath = self._vpath(path)
        with self._lock:
            has_open_fd = any(v == vpath for v in self._open_files.values())
            if has_open_fd:
                # Defer — the last release() will do the actual delete.
                self._pending_unlink.add(vpath)
                return
            self.volume.delete(vpath)
            self._file_buffers.pop(vpath, None)
            self._deferred_attrs.pop(vpath, None)
            self._hidden_seen.discard(vpath)      # libfuse's own cleanup
            self._invalidate_cached(vpath)
            self._dirty_files.discard(vpath)
            self._persist_locked()

    def rename(self, old: str, new: str) -> None:
        """Rename a file or directory (subtree re-keyed for directories)."""
        self._writable(old)
        old_vp = self._vpath(old)
        new_vp = self._vpath(new)
        with self._lock:
            # POSIX: the source pathname is unusable after unlink().
            # Rename of an unlinked-but-open path must behave like the
            # source doesn't exist.
            if old_vp in self._pending_unlink:
                raise OSError(errno.ENOENT, "No such file or directory", old)
            # POSIX no-op, mirroring the container-level guard.  Without
            # this, the file branch below pops the destination buffer —
            # which IS the source's — and discards its dirty flag before
            # re-keying, silently losing every unflushed write.
            if new_vp == old_vp:
                return
            # Destination held by an unlinked-but-still-open file: our
            # buffers are vpath-keyed (same reasoning as create()), so
            # letting the rename land would corrupt the old fds' view and
            # the deferred delete on their last close would destroy the
            # freshly renamed file.  Refuse until those fds close.
            if new_vp in self._pending_unlink:
                raise OSError(
                    errno.EBUSY,
                    "Destination was unlinked but still has open fds", new)
            is_dir = (
                self.volume.get_entry(old_vp) is None
                and self.volume.get_entry(self._dir_vpath(old)) is not None
            )
            if is_dir:
                old_prefix = self._dir_vpath(old)
                new_prefix = self._dir_vpath(new)
                # A pending-unlink child still has open fds whose deferred
                # delete is keyed to the old path — renaming the parent
                # would strand the entry under its new name.
                if any(vp.startswith(old_prefix)
                       for vp in self._pending_unlink):
                    raise OSError(
                        errno.EBUSY,
                        "Directory contains unlinked files with open fds",
                        old)
                self.volume.rename(old_vp, new_vp)
                for h in [h for h in self._hidden_seen if h.startswith(old_prefix)]:
                    self._hidden_seen.discard(h)
                    self._hidden_seen.add(new_prefix + h[len(old_prefix):])
                for vp in [v for v in self._file_buffers
                           if v.startswith(old_prefix)]:
                    self._file_buffers[new_prefix + vp[len(old_prefix):]] = \
                        self._file_buffers.pop(vp)
                for vp in [v for v in self._dirty_files
                           if v.startswith(old_prefix)]:
                    self._dirty_files.discard(vp)
                    self._dirty_files.add(new_prefix + vp[len(old_prefix):])
                for vp in [v for v in self._deferred_attrs
                           if v.startswith(old_prefix)]:
                    self._deferred_attrs[new_prefix + vp[len(old_prefix):]] = \
                        self._deferred_attrs.pop(vp)
                # fd → vpath tracking must follow too: release()/unlink()
                # compare these values against the path the kernel passes
                # AFTER the rename, and a stale value silently disables
                # the deferred-unlink machinery for open children.
                for fd_key, vp in self._open_files.items():
                    if vp.startswith(old_prefix):
                        self._open_files[fd_key] = \
                            new_prefix + vp[len(old_prefix):]
                self.cache.invalidate_prefix(old_prefix)
            else:
                self.volume.rename(old_vp, new_vp)
                # libfuse's hide-rename, and nothing else: the exact name
                # shape and a source that is open.  A user's own rename to
                # such a name is theirs to keep; a hidden name renamed away
                # (or over) stops being ours to sweep.
                self._hidden_seen.discard(old_vp)
                self._hidden_seen.discard(new_vp)
                if (_HIDDEN_RE.fullmatch(os.path.basename(new_vp))
                        and any(v == old_vp for v in self._open_files.values())):
                    self._hidden_seen.add(new_vp)
                # A replaced destination's buffered/cached content is gone;
                # drop it before re-keying the source's buffer into place.
                self._file_buffers.pop(new_vp, None)
                self._dirty_files.discard(new_vp)
                # ...and its deferred stamp: applied to the incoming content
                # it dated a fresh file with the replaced file's mtime, which
                # every incremental sync tool then took as "unchanged".
                self._deferred_attrs.pop(new_vp, None)
                self._invalidate_cached(new_vp)
                if old_vp in self._file_buffers:
                    self._file_buffers[new_vp] = self._file_buffers.pop(old_vp)
                self._invalidate_cached(old_vp)
                if old_vp in self._dirty_files:
                    self._dirty_files.discard(old_vp)
                    self._dirty_files.add(new_vp)
                if old_vp in self._deferred_attrs:
                    self._deferred_attrs[new_vp] = self._deferred_attrs.pop(old_vp)
                # Re-key open-fd tracking (see the dir branch for why).
                for fd_key, vp in self._open_files.items():
                    if vp == old_vp:
                        self._open_files[fd_key] = new_vp
            self._persist_locked()

    def chmod(self, path: str, mode: int) -> int:
        """Update mode, journaled and persisted like every other mutation."""
        self._writable(path)
        vpath = self._vpath(path)
        with self._lock:
            if vpath == "/":
                self._root_mode = stat.S_IFDIR | (mode & 0o7777)
                return 0
            if vpath in self._pending_unlink:
                raise OSError(errno.ENOENT, "No such file or directory", path)
            if vpath in self._dirty_files:
                # cp -p and ditto fchmod *before* close: the write record the
                # flush emits carries the mode, so journaling it now cost a
                # second append and fsync per copied file.
                self._defer(vpath, mode=mode)
                return 0
            if not self.volume.set_attrs(vpath, mode=mode):
                raise OSError(errno.ENOENT, "No such file or directory", path)
            # unzip and tar -x set attributes *after* close, so the
            # release() that persisted the data has already run; without a
            # persist here the change lived only in memory until the next
            # mutating op.
            self._persist_locked()
        return 0

    def utimens(self, path: str, times: tuple | None = None) -> int:
        """Update mtime, journaled so it survives unmount.

        This is what cp -p, rsync -t, unzip, tar -x and Finder issue after
        writing a file, so dropping it silently re-stamped every copied file
        with its copy time and broke incremental sync.  The value is kept at
        the precision fusepy delivers: truncating to whole seconds made
        full-precision comparers (rsync 3 on both ends) re-copy every file.
        """
        self._writable(path)
        mtime = _decode_fuse_mtime(times[1] if times else None)
        vpath = self._vpath(path)
        with self._lock:
            if vpath == "/":
                if mtime is not _OMIT:
                    self._root_mtime = mtime
                return 0
            if vpath in self._pending_unlink:
                raise OSError(errno.ENOENT, "No such file or directory", path)
            if mtime is _OMIT:
                if not self.volume.set_attrs(vpath):          # existence only
                    raise OSError(errno.ENOENT, "No such file or directory", path)
                return 0
            if vpath in self._dirty_files:
                # Unflushed data: the write record the flush emits carries
                # this stamp.  Kept only in the deferred map (getattr
                # overlays it), so a later write() that supersedes it also
                # reverts what the caller sees — the index and the disk
                # never disagree.
                self._defer(vpath, mtime=mtime)
                return 0
            if not self.volume.set_attrs(vpath, mtime=mtime):
                raise OSError(errno.ENOENT, "No such file or directory", path)
            self._persist_locked()
        return 0

    def chown(self, path: str, uid: int, gid: int) -> int:
        """Accept ownership changes as a no-op.

        fusepy answers EROFS for any setattr the filesystem leaves
        unimplemented, and BSD cp -p, ditto and rsync -a all chown after
        writing — so a volume the user had just written to reported
        "Read-only file system" (cp exit 1, rsync exit 23).  getattr reports
        every entry as the mounting user's, so there is nothing to record.
        """
        self._writable(path)
        vpath = self._vpath(path)
        if vpath == "/":
            return 0
        with self._lock:
            # set_attrs with nothing to change is an existence check that
            # understands the file/directory key difference.
            if vpath in self._pending_unlink or not self.volume.set_attrs(vpath):
                raise OSError(errno.ENOENT, "No such file or directory", path)
        return 0

    def save_all_dirty(self, apply_pending_unlink: bool = True,
                       lock_timeout: float | None = None) -> None:
        """Flush all dirty FUSE buffers to the volume, then persist the volume.

        Acquires the FUSE ops lock so this cannot race with an in-flight
        flush(), release(), write(), or other FS operation.  Used by
        unmount_volume() and _emergency_save_all() to ensure the volume on
        disk reflects the latest buffered writes.  Without this, an unmount
        or signal-driven shutdown could persist stale volume data even though
        the user's writes had already been accepted.

        Mirrors flush() / release(): writes to a path in ``_pending_unlink``
        are intentionally NOT persisted — the unlink-while-open semantics
        require the data to vanish on last close, and shutdown happens
        before release() has a chance to run the deferred delete.  Without
        this guard an editor's swap file (classic create + unlink + keep
        writing pattern) would be silently resurrected in the encrypted
        container on the next mount.

        ``apply_pending_unlink`` must be True only when shutdown is
        certain (exit/signal paths).  A caller that might CONTINUE serving
        afterwards — unmount_volume before its OS unmount, whose failure
        leaves the mount live — passes False: clearing the limbo set on a
        still-serving mount lets a later flush on the still-open fd write
        the deleted file straight back into the container.
        """
        if lock_timeout is None:
            self._lock.acquire()
        elif not self._lock.acquire(timeout=lock_timeout):
            # Signal path only. Skipping this volume leaves it exactly as a
            # SIGKILL would; hanging here would lose every other volume too.
            logger.warning(
                "Emergency save: could not acquire the lock for %s within "
                "%.1fs; skipping (a filesystem operation is still running)",
                self.volume.path, lock_timeout,
            )
            return
        try:
            if self.volume.read_only:
                # Under the lock: a FUSE worker may be inside release().
                if self._dirty_files:
                    logger.warning("%s: %d file(s) with unsaved changes dropped — "
                                   "the mount became read-only", self.volume.path,
                                   len(self._dirty_files))
                    logger.debug("dropped unsaved buffers: %s", sorted(self._dirty_files))
                    self._dirty_files.clear()
                return
            for vpath in list(self._dirty_files):
                if vpath in self._pending_unlink or vpath in self._hidden_seen:
                    # Doomed: forget nothing, as flush() does — a refused OS
                    # unmount leaves the mount serving, and the file's last
                    # release() decides its fate.
                    continue
                attrs = self._deferred_attrs.pop(vpath, None) or {}
                buf = self._file_buffers.get(vpath, bytearray())
                self._write_back(vpath, bytes(buf), attrs)
                self._dirty_files.discard(vpath)
            if apply_pending_unlink:
                self.apply_pending_unlinks()
            elif self.volume.is_dirty:
                self.volume.save()
        finally:
            self._lock.release()

    def apply_pending_unlinks(self) -> None:
        """Apply deferred unlinks whose fds will never see release().

        Call only once shutdown is certain (successful unmount, exit and
        signal paths).  The volume.delete() here is safe: if the path
        still has open fds, the kernel's subsequent release() will be a
        no-op for the delete (vpath already gone from dir_index).
        """
        with self._lock:
            if self.volume.read_only:
                # A true read-only mount holds nothing pending; a mount that
                # lost writability cannot save — either way a save here made
                # unmount_volume() raise after the OS unmount had succeeded.
                self._pending_unlink.clear()
                return
            for vpath in list(self._pending_unlink):
                try:
                    self.volume.delete(vpath)
                except FileNotFoundError:
                    pass
                self._invalidate_cached(vpath)
            self._pending_unlink.clear()
            # libfuse's own deferred unlinks: it renames an unlinked-while-
            # open file to `.fuse_hiddenXXXX` and removes it after the last
            # release, which macOS may not deliver before the unmount
            # (vnodes are reclaimed lazily).  Shutdown is certain here, so
            # the litter libfuse made in THIS session goes; nothing else
            # with that prefix is ours to remove.
            for vpath in sorted(self._hidden_seen):
                try:
                    self.volume.delete(vpath)
                    logger.debug("removed libfuse's hidden file %s at shutdown", vpath)
                except OSError:
                    pass
                self._invalidate_cached(vpath)
            self._hidden_seen.clear()
            if self.volume.is_dirty:
                self.volume.save()


# ── Mount / Unmount API ─────────────────────────────────────────────────────

_mounted_volumes: dict[str, dict] = {}  # mount_point → {thread, volume, fuse_obj}
# Serialises mount_volume() / unmount_volume() mutations of _mounted_volumes
# so concurrent UI clicks or scripted mounts can't observe torn state.
_mount_lock = threading.Lock()
# mount_point → fd holding the cross-process flock for that mount
_volume_locks: dict[str, int | None] = {}   # None: read-only mount, no lock


def _acquire_volume_lock(volume_path: str) -> int:
    """Advisory cross-process lock held for the life of a mount.

    The in-process double-mount guard can't see a second app instance or
    a script: two processes appending to one journal truncate each
    other's records (both do seek(_journal_end); truncate() with
    diverging bookkeeping).  A sidecar ``<volume>.lock`` file is flocked
    LOCK_EX|LOCK_NB — the .qcv itself cannot carry the lock because
    compact() replaces its inode via os.replace(), which would silently
    release an flock held on the old inode.  The 0-byte sidecar is never
    deleted (unlinking it would race a concurrent locker onto a fresh,
    unlocked inode).

    Returns the open fd (closing it releases the lock; process exit
    releases it automatically).  Raises RuntimeError when another
    process holds it.
    """
    import fcntl
    # Canonicalize: a symlinked or differently-spelled path to the same
    # volume must contend for the SAME lock file, or the guard is
    # bypassable by aliasing.
    real = os.path.realpath(volume_path)
    lock_path = real + ".lock"
    try:
        # No symlink following: in a shared folder a planted link would put
        # the flock on some other inode and let two mounts each "hold" it.
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except PermissionError:
        # mount_volume() takes this lock only for a writable container in a
        # writable directory (anything else is served read-only without
        # one).  The usual reason is a sidecar another user owns (0600):
        # they have, or had, this volume mounted, and a per-user lock
        # elsewhere would let both append to one journal.  A sidecar the
        # caller owns but cannot open (`chmod -R a-w` on the vault folder,
        # then only the folder restored) or a directory/symlink in its
        # place is a permissions problem, not another user.
        try:
            owner = os.stat(lock_path).st_uid
        except OSError:
            owner = None
        if owner is not None and owner != os.getuid():
            raise RuntimeError(
                f"{os.path.basename(real)} is in use by another user (the lock "
                f"file {os.path.basename(lock_path)} is not yours). Unmount it "
                "there first, or remove the lock file if it is stale."
            ) from None
        raise RuntimeError(
            f"{os.path.basename(real)} cannot be mounted: its lock file "
            f"{os.path.basename(lock_path)} could not be opened (permission "
            "denied). Fix the file's permissions or remove it."
        ) from None
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            what = "a symbolic link"
        elif exc.errno == errno.EISDIR:
            what = "a folder"
        else:
            raise
        raise RuntimeError(
            f"{os.path.basename(real)} cannot be mounted: {os.path.basename(lock_path)} "
            f"is {what}, not a regular file. Remove it and try again."
        ) from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise RuntimeError(
            f"{os.path.basename(real)} cannot be mounted: {os.path.basename(lock_path)} "
            "is not a regular file. Remove it and try again."
        )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
            os.close(fd)
            raise RuntimeError(
                "Volume appears to be mounted by another process "
                f"(lock held on {os.path.basename(lock_path)}). "
                "Unmount it there first."
            ) from None
        # ENOLCK / EOPNOTSUPP: the filesystem cannot lock at all (some NFS
        # and SMB mounts).  Blaming "another process" sent the user hunting
        # for one that does not exist; mount with the in-process guard only.
        logger.warning("flock unsupported on %s (%s); relying on the "
                       "in-process mount guard only", lock_path, exc.strerror)
    return fd


def _container_writable(real_vol: str) -> bool:
    """True when both the container and its directory accept writes: the
    journal appends to the file, compaction writes a temp file beside it."""
    directory = os.path.dirname(real_vol) or "."
    return os.access(real_vol, os.W_OK) and os.access(directory, os.W_OK)


#: Entries Finder or the OS drop into any folder it displays; none of them is
#: user content, so none should make an otherwise-empty mount point unusable.
_IGNORED_MOUNT_POINT_ENTRIES = frozenset({".DS_Store", ".localized", "Icon\r"})


def _volname_for(volume_path: str) -> str:
    """Finder sidebar name for a mount: the container's stem, so two
    mounted vaults are not both called "QuantaCrypt".  The value travels as
    a ``-o volname=`` mount option, so commas and control characters are
    replaced and the length is bounded."""
    stem = os.path.splitext(os.path.basename(volume_path))[0]
    cleaned = "".join(ch if (ch.isalnum() or ch in " ._-") else "_"
                      for ch in stem).strip(" ._-")
    return cleaned[:64] or "QuantaCrypt"


def _release_volume_lock(mount_point: str) -> None:
    fd = _volume_locks.pop(mount_point, None)
    if fd is not None:
        try:
            os.close(fd)  # closing the fd releases the flock
        except OSError:
            pass


def _reap_dead_mounts_locked() -> None:
    """Drop tracking for mounts whose FUSE worker has exited.

    Caller must hold ``_mount_lock``.  An external eject (Finder,
    ``umount``, backend crash) ends the worker thread without ever going
    through unmount_volume(): the tracking entry and its cross-process
    flock would otherwise persist for the process lifetime — every
    remount of that volume fails with "mounted by another process" and
    the UI keeps listing a mount that no longer exists.  Best-effort
    save first: the kernel flushed on eject via release(), but buffered
    volume state may remain.  Entries with ``thread`` None (direct API /
    test injection) are left alone — liveness is unknowable for them.
    """
    for mp, info in list(_mounted_volumes.items()):
        t = info.get("thread")
        if t is None or t.is_alive():
            continue
        logger.warning(
            "Mount at %s ended outside unmount_volume (external eject?); "
            "reclaiming its tracking entry and lock", mp)
        try:
            fuse_obj = info.get("fuse")
            if fuse_obj is not None:
                fuse_obj.save_all_dirty(apply_pending_unlink=True)
            elif info["volume"].is_dirty:
                info["volume"].save()
        except Exception as exc:  # noqa: BLE001 — reported, not hidden
            logger.error("post-eject save failed: %s", safe_reason(exc))
            logger.info("post-eject save failure at %s", mp, exc_info=True)
        try:
            sidecar = info["volume"].rescue_if_orphaned()
            if sidecar:
                logger.info("orphaned container at %s preserved to %s", mp, sidecar)
        except Exception:  # noqa: BLE001 — best effort
            pass
        _mounted_volumes.pop(mp, None)
        _release_volume_lock(mp)

# How long mount_volume() waits for the FUSE worker to either successfully
# start serving or fail synchronously.  If FUSE() raises (missing backend,
# unwritable mount point, busy target) the thread dies inside this window
# and we propagate the exception instead of registering a zombie mount.
_FUSE_STARTUP_TIMEOUT = 2.0
# Bound on the external unmount tool. Held under _mount_lock, so an
# unbounded call here blocks every other mount operation in the process.
_UNMOUNT_TIMEOUT = 30.0

#: Sentinel: utimens was asked to leave the mtime alone.
_OMIT = object()


def _decode_fuse_mtime(raw: float | None):
    """The mtime fusepy hands utimens, minus libfuse's sentinels.

    libfuse always passes both timespecs; the one the kernel did not set
    has tv_sec=0 and tv_nsec=UTIME_OMIT/UTIME_NOW — (1<<30)-2/-1 on the
    libfuse side (what macFUSE was seen to send), -2/-1 in Darwin's own
    headers — which fusepy's time_of_timespec turns into a few nanoseconds
    either side of zero.  Decode the nanosecond field rather than matching
    one float, and clamp at 0 so a negative fraction cannot come back out
    of getattr as an invalid negative tv_nsec.  Storing the OMIT sentinel
    stamped an atime-only `touch -a` with 1970.
    """
    if raw is None:
        return time.time()
    ns = round(raw * 1e9)
    if ns in (-1, 1073741823):
        return time.time()
    if ns in (-2, 1073741822):
        return _OMIT
    if raw < 0:
        # A pre-1970 stamp is representable; only a negative *fraction* would
        # come back out as an invalid negative tv_nsec.
        return float(math.floor(raw))
    return float(raw)

#: How much of a file the write path holds in RAM at once, as a multiple of
#: its size: the write buffer, the bytes() snapshot, the per-chunk ciphertext
#: list, and the joined result.
_WRITE_MEMORY_FACTOR = 4


def _max_writable_bytes() -> int:
    """Largest file the in-memory write path can be expected to handle."""
    try:
        total_ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        return 1 << 40      # unknown: do not constrain
    # Half of physical memory, divided by the copies the write path makes.
    return max(total_ram // 2 // _WRITE_MEMORY_FACTOR, 64 * 1024 * 1024)

# ── Graceful shutdown ──────────────────────────────────────────────────────

_atexit_registered = False
_signals_registered = False
_shutdown_lock = threading.Lock()


def _emergency_save_all(lock_timeout: float | None = None) -> None:
    """Save all dirty mounted volumes.

    Called by atexit and signal handlers to prevent data loss on
    app exit or crash.  Routes through QuantaCryptFUSE.save_all_dirty()
    so that buffered writes not yet flushed are still persisted.
    Errors are logged but never raised so that the shutdown sequence
    is not interrupted.

    ``lock_timeout`` bounds each volume's lock acquisition; the signal path
    passes one so a FUSE worker holding the lock cannot hang the process.
    atexit passes None, because there it is safe to wait.
    """
    for mp in list(_mounted_volumes):
        info = _mounted_volumes.get(mp)
        if info is None:
            continue
        try:
            fuse_obj = info.get("fuse")
            if fuse_obj is not None:
                logger.info("Shutdown: saving dirty state for volume at %s", mp)
                fuse_obj.save_all_dirty(lock_timeout=lock_timeout)
            else:
                vc = info["volume"]
                if vc.is_dirty:
                    vc.save()
        except Exception as exc:  # noqa: BLE001 — reported, not hidden
            logger.error("shutdown: a volume could not be saved: %s", safe_reason(exc))
            logger.info("shutdown save failure at %s", mp, exc_info=True)
        try:
            vc = info["volume"]
            sidecar = vc.rescue_if_orphaned()
            if sidecar:
                logger.info("shutdown: orphaned container at %s preserved to %s", mp, sidecar)
        except Exception:  # noqa: BLE001 — best effort
            pass


#: How long the signal path waits for a volume's lock before giving up on
#: that volume. Python runs signal handlers on the main thread between
#: bytecodes, so an unbounded acquire here hangs the whole process when a
#: FUSE worker is mid-write — the caller then escalates to SIGKILL and the
#: buffer is lost, which is the exact outcome this handler exists to prevent.
_SIGNAL_SAVE_TIMEOUT = 2.0


def _signal_handler(signum: int, frame: Any) -> None:
    """Handle SIGTERM / SIGINT by saving volumes then re-raising.

    Bounded, not best-effort-forever: see _SIGNAL_SAVE_TIMEOUT. A volume
    whose lock cannot be taken in time is skipped and logged rather than
    hanging the process; its data is no worse off than under SIGKILL.

    NOTE: qc-core never reaches this. `_ensure_shutdown_handlers` is only
    ever called from a worker thread there, so `signal.signal` raises
    ValueError and the signal half stays unlatched, leaving cli.py's own
    handler (which sets a flag and lets the main loop unmount) in charge.
    That is load-bearing — a future synchronous startup remount from the
    helper's main thread would silently replace it with this one.
    """
    _emergency_save_all(lock_timeout=_SIGNAL_SAVE_TIMEOUT)
    # Re-raise with default handler so the process actually exits
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


def _ensure_shutdown_handlers() -> None:
    """Register atexit + signal handlers (each once, independently).

    The two halves latch separately: signal.signal() only works on the
    main thread, and mounts from the GUI always run on a worker.  With a
    single latch the worker's failed signal install was recorded as done
    and SIGTERM never saved anything (atexit does not run on SIGTERM).
    Now the signal half stays unlatched until a main-thread call — such
    as install_shutdown_handlers() at app startup — succeeds; every
    mount retries it, so script/CLI main-thread mounts self-heal too.
    """
    global _atexit_registered, _signals_registered  # noqa: PLW0603
    with _shutdown_lock:
        if not _atexit_registered:
            atexit.register(_emergency_save_all)
            _atexit_registered = True
        if not _signals_registered:
            try:
                signal.signal(signal.SIGTERM, _signal_handler)
                signal.signal(signal.SIGINT, _signal_handler)
                _signals_registered = True
            except ValueError:
                # Not the main thread — leave unlatched so a later
                # main-thread call can install the handlers.
                pass


def install_shutdown_handlers() -> None:
    """Install the emergency-save handlers from the main thread.

    Call once at app startup (the GUI's main() does).  Safe to call from
    any thread — off-main-thread the signal half simply stays pending.
    """
    _ensure_shutdown_handlers()


def mount_volume(
    volume_path: str,
    final_key: bytes,
    mount_point: str,
    foreground: bool = False,
    cache_mb: int = 100,
    credential_proven: bool = False,
) -> QuantaCryptFUSE:
    """Mount a .qcv volume at the given mount point.

    If foreground=True, blocks until unmounted. Otherwise starts a
    background thread and returns immediately.

    ``credential_proven`` says *final_key* came out of this volume's own
    auth block (derive_volume_key_* succeeded, so the KEM private key
    unsealed): a metadata failure inside open() is then reported as
    tampering rather than as a possibly wrong password.

    Raises RuntimeError if fusepy is not available or if the volume
    (by real path) is already mounted.
    """
    _ensure_shutdown_handlers()

    real_vol = os.path.realpath(volume_path)

    # Fast-path double-mount guard.  Snapshot the dict under the lock so
    # we never iterate a dict that a concurrent mount / unmount might
    # resize ("RuntimeError: dictionary changed size during iteration").
    # The lock-held re-check below is the race-safe guarantee against
    # double-registration; this snapshot is just for the fast error.
    # Reap externally-ended mounts first so an ejected volume doesn't
    # block its own remount forever.
    with _mount_lock:
        _reap_dead_mounts_locked()
        _mounted_snapshot = list(_mounted_volumes.items())
    for mp, info in _mounted_snapshot:
        if os.path.realpath(info["volume_path"]) == real_vol:
            raise RuntimeError(
                f"Volume is already mounted at {mp}. "
                "Unmount it first before mounting again."
            )

    available, msg = check_fuse_available()
    if not available:
        raise RuntimeError(msg)

    from fuse import FUSE  # type: ignore[import-untyped]

    # Cross-process guard: acquire the flock BEFORE the container reads
    # its journal bookkeeping.  Opening first would let a mount racing
    # another process's unmount snapshot a stale _journal_end and, once
    # it wins the lock, truncate records the other process committed in
    # between.  Held from here until handed to _volume_locks (background
    # success) or closed (foreground return / any failure).
    # A container that cannot be written — read-only media, a locked share,
    # a foreign folder (compaction needs the directory too) — is served
    # read-only: every mutation is refused before it touches state and no
    # save ever runs.  Mounting it read-write and failing at close() left
    # phantom entries in the namespace and an unmount that could not save.
    read_only = not _container_writable(real_vol)
    lock_fd: int | None
    if read_only:
        # Two readers cannot corrupt a journal, so the exclusive sidecar
        # lock (which the location may refuse anyway) is not taken.
        logger.info("Mounting %s read-only: the container or its folder "
                    "refuses writes", volume_path)
        lock_fd = None
    else:
        lock_fd = _acquire_volume_lock(volume_path)
    lock_owned = True
    try:
        # Open the volume (under the cross-process lock)
        # The resolved path: the lock and the writability probe already use
        # it, and compact()'s os.replace through a symlink would otherwise
        # turn the link into a second, diverging copy (review run 19 F-201).
        vc = VolumeContainer(real_vol, final_key)
        vc.open(credential_proven=credential_proven)
        vc.read_only = read_only

        # Create mount point if needed.  An existing, non-empty directory
        # is refused: mounting over it hides its contents until unmount,
        # and a mistyped path silently landing on a real folder was the
        # documented way to lose track of files (review F-035).
        # Finder drops .DS_Store into any folder it shows, and the default
        # mount folder persists empty between mounts — so counting it as
        # content dead-ended the very path the app suggests.
        # The Tk manager's own hint says "e.g. ~/QuantaCrypt Volumes/<name>";
        # passed raw, makedirs made a folder literally named `~` under the
        # process CWD (run 18 F-203).
        mount_point = os.path.expanduser(mount_point)
        if os.path.lexists(mount_point) and not os.path.isdir(mount_point):
            # A file (or a dangling symlink) at the path: makedirs would
            # have reported it as "already exists — choose a different
            # name", a story about the volume, not the mount point.
            raise InvalidInput(
                f"Mount point {mount_point!r} exists but is not a folder. "
                "Choose an empty or new folder.")
        if os.path.isdir(mount_point):
            entries = [e for e in os.listdir(mount_point)
                       if e not in _IGNORED_MOUNT_POINT_ENTRIES]
            if entries:
                raise InvalidInput(
                    f"Mount point {mount_point!r} is not empty (it contains "
                    f"{entries[0]!r}). Choose an empty or new folder so nothing "
                    "is hidden under the mounted volume."
                )
        os.makedirs(mount_point, exist_ok=True)

        fuse_obj = QuantaCryptFUSE(vc, cache_mb=cache_mb)
        fuse_opts: dict[str, Any] = {"allow_other": False}
        if sys.platform == "darwin":
            # A macFUSE / FUSE-T option; libfuse on Linux rejects unknown
            # -o options and the mount fails before serving.
            fuse_opts["volname"] = _volname_for(volume_path)
        if read_only:
            fuse_opts["ro"] = True

        if foreground:
            try:
                FUSE(fuse_obj, mount_point, foreground=True, nothreads=True,
                     **fuse_opts)
            finally:
                # The kernel has already torn the mount down when FUSE()
                # returns; nothing else runs the end-of-mount save that
                # unmount_volume() gives background mounts, so pending
                # chmod/utimens records and deferred unlinks would be lost.
                fuse_obj.save_all_dirty(apply_pending_unlink=True)
            return fuse_obj  # finally releases the lock post-unmount

        # Background mount: wait for FUSE to either start serving or fail
        # synchronously, and only register _mounted_volumes on success.
        # Registering unconditionally would leave a zombie entry after a
        # failed FUSE startup (missing FUSE-T, busy mount point), and a
        # later unmount_volume() would run diskutil / fusermount against
        # a path we never actually mounted.
        startup_error: list[BaseException] = []
        ready = threading.Event()

        def _run():
            try:
                FUSE(fuse_obj, mount_point, foreground=True, nothreads=True,
                     **fuse_opts)
            except BaseException as exc:  # noqa: BLE001
                startup_error.append(exc)
            finally:
                ready.set()

        # The duplicate check, worker start, and registration must be one
        # atomic step under _mount_lock.  With the check outside the lock,
        # two racers could both pass it and both spawn live mounts on the
        # same .qcv — the loser's raise then left a serving, UNTRACKED
        # mount (unreachable by unmount / emergency save) whose journal
        # appends interleave with the winner's truncate+write sequences
        # and corrupt the container.  mount/unmount are already fully
        # serialised elsewhere; holding the lock for the ≤2 s startup
        # window is fine for a single-user app.
        with _mount_lock:
            for mp, info in _mounted_volumes.items():
                if os.path.realpath(info["volume_path"]) == real_vol:
                    raise RuntimeError(
                        f"Volume is already mounted at {mp}. "
                        "Unmount it first before mounting again."
                    )

            t = threading.Thread(target=_run, daemon=True)
            t.start()

            # A live FUSE() blocks serving requests, so `ready` — set in the
            # worker's finally — is the authoritative signal: if it fires
            # inside the startup window, FUSE() returned or raised and the
            # mount is NOT up.
            #
            # This used to test `t.is_alive()` instead, which is a race: the
            # worker sets `ready` and then still has to unwind before it
            # stops being alive, so the main thread could observe a live
            # thread for an already-failed mount and register it. macOS
            # happened to lose that scheduling race and Linux won it, which
            # is why two mount tests passed locally and failed on CI with
            # "DID NOT RAISE".
            failed_fast = ready.wait(timeout=_FUSE_STARTUP_TIMEOUT)
            if failed_fast:
                if startup_error:
                    raise RuntimeError(
                        f"FUSE mount failed: {startup_error[0]}"
                    ) from startup_error[0]
                raise RuntimeError(
                    "FUSE worker thread exited before the mount was "
                    "established"
                )

            _mounted_volumes[mount_point] = {
                "thread": t,
                "volume": vc,
                "fuse": fuse_obj,
                "volume_path": volume_path,
                "read_only": read_only,
            }
            _volume_locks[mount_point] = lock_fd
            lock_owned = False

        return fuse_obj
    finally:
        if lock_owned and lock_fd is not None:
            os.close(lock_fd)


def unmount_volume(mount_point: str) -> None:
    """Unmount a volume and save any pending changes.

    Saves dirty data (including buffered FUSE writes) **before** removing
    from the tracking dict so that ``_emergency_save_all`` can still reach
    the volume if save() fails.  The external unmount subprocess is only
    invoked for paths we actually own — we do not run diskutil/fusermount
    against an arbitrary path passed in by a caller.

    The whole body runs under ``_mount_lock``.  If we dropped the lock
    between ``pop`` and the ``diskutil`` / ``fusermount`` subprocess, a
    concurrent ``mount_volume()`` for a different volume at the same
    mount_point could slot in its fresh mount — and our still-in-flight
    subprocess would then tear down the new one.  Holding the lock makes
    mount/unmount fully serialised, which matches the UI's
    single-user-at-a-time intent.
    """
    import subprocess
    import sys

    mount_point = os.path.expanduser(mount_point)   # as mount_volume tracks it
    with _mount_lock:
        _reap_dead_mounts_locked()
        info = _mounted_volumes.get(mount_point)
        if info is None:
            # The common cause is an external eject (Finder, `umount`)
            # between the list poll and the click: the volume is already
            # gone, not damaged.  InvalidInput (a ValueError) so it does not
            # classify as `format`; the front ends read it as "already
            # unmounted" (review run 20 F-007).
            raise InvalidInput(
                f"No volume is mounted at {mount_point!r}. It may already "
                "have been ejected."
            )

        # Save state *before* anything else so that if save_all_dirty()
        # fails, _emergency_save_all can still find the volume for a retry.
        # Deferred unlinks are NOT applied yet: if the OS unmount below
        # fails, the mount keeps serving, and a cleared limbo set would
        # let a later flush resurrect the deleted files.
        fuse_obj = info.get("fuse")
        try:
            if fuse_obj is not None:
                fuse_obj.save_all_dirty(apply_pending_unlink=False)
            elif info["volume"].is_dirty:
                info["volume"].save()
        except OSError as exc:
            if not (isinstance(exc, PermissionError)
                    or exc.errno in (errno.EROFS, errno.ESTALE)):
                raise
            # The layout stopped accepting writes after the mount (or the
            # container was replaced beneath it).  Keeping the mount alive
            # cannot save anything; unmount and say what was lost rather
            # than "in use by another application".
            info["volume"].read_only = True
            sidecar = info["volume"].rescue_if_orphaned()
            logger.error("buffered changes could not be saved before unmount "
                         "(%s); unmounting anyway%s", safe_reason(exc),
                         " (the volume as this mount had it was preserved beside it)"
                         if sidecar else "")
            logger.info("unsaved changes at %s%s", mount_point,
                        f"; preserved to {sidecar}" if sidecar else " lost")
            rescued_here = True
        else:
            rescued_here = False

        # Rescue an orphaned inode even when the save above did not raise: a
        # mount whose container was replaced externally with nothing dirty
        # since has no failed save to trigger it, and a clean Eject would
        # free the last descriptor silently (review run 21 F-003).  Skipped
        # when the except above already rescued (it logged the sidecar), so
        # one event is one log line (review run 22 F-001).
        if not rescued_here:
            try:
                fuse_obj_ = info.get("fuse")
                vc_ = fuse_obj_.volume if fuse_obj_ is not None else info.get("volume")
                sidecar_ = vc_.rescue_if_orphaned() if vc_ is not None else None
                if sidecar_:
                    logger.info("orphaned container at %s preserved to %s", mount_point, sidecar_)
            except Exception:  # noqa: BLE001 — best effort
                pass

        # Use platform-appropriate unmount.  Still under the lock so a
        # concurrent remount at the same mount_point can't race our
        # subprocess into tearing down the new mount.
        if sys.platform == "darwin":
            cmd = ["diskutil", "unmount", mount_point]
        else:
            # Some distros ship only fusermount3 (libfuse3).
            import shutil
            tool = "fusermount3" if shutil.which("fusermount3") else "fusermount"
            cmd = [tool, "-u", mount_point]
        # Bounded: this runs while _mount_lock is held, so a diskutil that
        # never returns (wedged FUSE mount, busy filesystem) would pin the
        # lock forever and block every later mount, unmount, list and the
        # service's own shutdown loop. A timeout is treated as a failed
        # unmount, which is exactly the branch below.
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=_UNMOUNT_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"Unmount of {mount_point} timed out after {_UNMOUNT_TIMEOUT}s. "
                "The volume may be in use by another application"
            ) from None
        if result.returncode != 0:
            # The volume is still mounted and serving — keep it tracked so
            # emergency save and a retry can reach it, and so the double-
            # mount guard keeps a second writer off this journal.
            detail = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(
                f"Unmount of {mount_point} failed"
                f"{': ' + detail if detail else ''}. "
                "The volume may be in use by another application"
            )

        # Shutdown of this mount is now certain: apply the deferred
        # unlinks the pre-unmount save intentionally skipped (a clean
        # unmount usually already ran them via release(); this covers
        # fds that never saw one).  Tracking and the flock are dropped in
        # a finally — a failure in the unlink application must not strand
        # a permanently-tracked, permanently-locked entry for a mount the
        # OS has already torn down.
        try:
            if fuse_obj is not None:
                fuse_obj.apply_pending_unlinks()
        except (OSError, ValueError) as exc:
            # The OS unmount already succeeded: raising here told the user
            # the volume was stuck when it was gone, and a retry found no
            # mount to act on.  What could not be persisted (deferred
            # deletes, libfuse's litter) simply reappears at the next mount.
            # ValueError is save()'s own refusal (a container truncated
            # beneath the mount): the same "could not persist" story.
            logger.error("deferred deletes could not be persisted after "
                         "unmount (%s); they will reappear at the next mount",
                         safe_reason(exc))
            logger.info("deferred deletes not persisted at %s", mount_point,
                        exc_info=True)
        finally:
            _mounted_volumes.pop(mount_point, None)
            _release_volume_lock(mount_point)


def get_mounted_volumes() -> dict[str, dict]:
    """Return dict of currently mounted volumes: mount_point → info.

    Reaps externally-ended mounts first so callers (the Volume Manager
    list, the create-guard) see reality, not stale tracking.
    """
    with _mount_lock:
        _reap_dead_mounts_locked()
        for info in _mounted_volumes.values():
            # A mount that lost writability flipped the container, not the
            # tracking entry; every list consumer wants the live answer.
            vc = info.get("volume")
            if vc is not None:
                info["read_only"] = bool(getattr(vc, "read_only", False))
        return dict(_mounted_volumes)
