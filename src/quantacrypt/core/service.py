"""JSON-lines service that drives the core for any front end.

See docs/design/core-service-protocol.md.  One request per stdin line, one
event per stdout line; long operations run on worker threads and report
``progress`` events; ``cancel`` flips the request's token.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
import uuid
from errno import EEXIST as errno_EEXIST
from typing import Any, Callable, IO

from quantacrypt import __version__
from quantacrypt.core import crypto as cc
from quantacrypt.core import package as pkg
from quantacrypt.core.errors import (InvalidInput, InvalidRequest, classify_error,
                                     safe_reason)

log = logging.getLogger("quantacrypt.service")

CONTROL_OPS = ("cancel", "shutdown", "ping", "version")

# How long the EOF path lets in-flight work finish before cancelling it —
# a wedged worker must not keep an orphaned helper (and its mounts) alive.
EOF_GRACE_SECONDS = 300.0
JOIN_SECONDS = 5.0


class ServiceStop(BaseException):
    """Raised from the SIGTERM handler on the main thread so the blocked
    stdin read unwinds (PEP 475: a handler that raises is not retried)."""

# (keyword, stage id, label) — first match wins, so put specific before broad.
_STAGE_MAP = [
    ("compress",       "compress", "Compressing folder"),
    ("argon2",         "kdf",      "Securing password"),
    ("decrypting kyber", "unlock", "Unlocking key"),
    ("decapsulat",     "unlock",   "Unlocking key"),
    ("combining",      "split",    "Combining shares"),
    ("private key",    "lock",     "Locking key"),
    ("keypair",        "kem",      "Generating protection"),
    ("kyber",          "kem",      "Generating protection"),
    ("encapsulat",     "kem",      "Generating protection"),
    ("master key",     "kem",      "Generating protection"),
    ("splitting",      "split",    "Splitting key"),
    ("decrypting payload", "payload", "Decrypting file"),
    ("payload",        "payload",  "Encrypting file"),
    ("integrity",      "verify",   "Checking integrity"),
    ("writing",        "write",    "Saving"),
    ("reading",        "read",     "Reading volume"),
    ("mount",          "mount",    "Mounting"),
]
_PCT_RE = re.compile(r"(\d{1,3})%")


def stage_for(message: str) -> tuple[str, str, float | None]:
    """Map a raw core progress string to (stage, label, pct-or-None)."""
    low = message.lower()
    stage, label = "work", message
    for kw, sid, lbl in _STAGE_MAP:
        if kw in low:
            stage, label = sid, lbl
            break
    m = _PCT_RE.search(message)
    pct = min(int(m.group(1)), 100) / 100.0 if m else None
    return stage, label, pct


class _Request:
    __slots__ = ("id", "op", "params", "cancelled", "thread")

    def __init__(self, rid: str, op: str, params: dict):
        self.id = rid
        self.op = op
        self.params = params
        self.cancelled = threading.Event()
        self.thread: threading.Thread | None = None


class Service:
    """Dispatcher.  Construct with text streams; call ``run()`` to serve
    until EOF/shutdown, or ``handle_line()`` from tests."""

    def __init__(self, reader: IO[str], writer: IO[str], *,
                 exit_fn: Callable[[], None] | None = None):
        self._in = reader
        self._out = writer
        self._wlock = threading.Lock()
        self._reqs: dict[str, _Request] = {}
        self._rlock = threading.Lock()
        self._stopping = False
        self._shutdown_started = False
        self._shutdown_lock = threading.Lock()
        self._exit_fn = exit_fn
        self.ops: dict[str, Callable[[dict, "_Ctx"], dict]] = {
            "fuse_check": op_fuse_check,
            "inspect": op_inspect,
            "encrypt": op_encrypt,
            "decrypt": op_decrypt,
            "volume_inspect": op_volume_inspect,
            "volume_create": op_volume_create,
            "volume_mount": op_volume_mount,
            "volume_unmount": op_volume_unmount,
            "volume_list": op_volume_list,
        }

    # ── I/O ──────────────────────────────────────────────────────────────────

    def emit(self, obj: dict) -> None:
        # allow_nan=False: Python would happily write NaN/Infinity, which
        # no strict JSON decoder (the Swift client's included) accepts —
        # the line would be dropped and the request would never finish.
        # Failing here turns that into an error event instead.
        line = json.dumps(obj, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False)
        with self._wlock:
            self._out.write(line + "\n")
            self._out.flush()

    def _error(self, rid: Any, code: str, message: str, detail: str = "") -> None:
        self.emit({"id": rid, "event": "error", "code": code,
                   "message": message, "detail": detail})

    # ── Loop ─────────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Serve until EOF, ``shutdown`` or ``request_stop``.

        EOF means "no more requests": in-flight work is allowed to finish
        (a one-shot client may write its request and close the pipe) for up
        to ``EOF_GRACE_SECONDS``, then volumes are unmounted and the process
        exits.  The ``shutdown`` op and SIGTERM are the abrupt form: they
        cancel in-flight work first.
        """
        try:
            try:
                for line in self._in:
                    self.handle_line(line)
                    if self._stopping:
                        break
            except ServiceStop:
                pass
        finally:
            if not self._stopping:
                self.wait_idle(timeout=EOF_GRACE_SECONDS)
            # Teardown once (a shutdown op may already have done it), then
            # always leave: the exit must not depend on who tore down.
            self.shutdown(exit_after=False)
            if self._exit_fn:
                self._exit_fn()

    def request_stop(self) -> None:
        """Flag the loop to stop and cancel workers.  Does NOT touch stdin:
        closing a file another thread is blocked reading deadlocks on the
        buffer lock (and inside a signal handler it is a reentrant call).
        The SIGTERM handler raises ``ServiceStop`` after calling this so the
        main thread's blocked read unwinds; a caller on another thread must
        write a line (even an empty one) to wake the loop.  All teardown
        happens in ``run()``'s ``finally`` on the main thread, never inside
        the signal handler (which could otherwise re-enter ``_mount_lock``)."""
        self._stopping = True
        with self._rlock:
            reqs = list(self._reqs.values())
        for r in reqs:
            r.cancelled.set()

    def handle_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        try:
            req = json.loads(line)
        except ValueError as exc:
            self._error(None, "invalid_request", "Request is not valid JSON.", str(exc))
            return
        if not isinstance(req, dict) or not isinstance(req.get("op"), str):
            self._error(req.get("id") if isinstance(req, dict) else None,
                        "invalid_request", "Request needs an 'op' string.")
            return
        rid = req.get("id")
        if rid is None:
            rid = f"auto-{uuid.uuid4().hex[:12]}"   # never collides with a live id
        rid = str(rid)
        op = req["op"]
        params = req.get("params") or {}
        if not isinstance(params, dict):
            self._error(rid, "invalid_request", "'params' must be an object.")
            return

        if op in CONTROL_OPS:
            self._control(rid, op, params)
            return
        handler = self.ops.get(op)
        if handler is None:
            self._error(rid, "invalid_request", f"Unknown op {op!r}.")
            return
        log.info("request %s op=%s", rid, op)   # ids and ops only — never params
        with self._rlock:
            if rid in self._reqs:
                self._error(rid, "invalid_request", f"Request id {rid!r} is already running.")
                return
            r = _Request(rid, op, params)
            self._reqs[rid] = r
        t = threading.Thread(target=self._run_request, args=(r, handler),
                             name=f"qc-{op}-{rid}", daemon=True)
        r.thread = t
        t.start()

    def _control(self, rid: str, op: str, params: dict) -> None:
        if op == "ping":
            self.emit({"id": rid, "event": "done", "result": {}})
        elif op == "version":
            self.emit({"id": rid, "event": "done", "result": {
                "version": __version__,
                "format_version": cc.MAX_FORMAT_VERSION,
                "platform": sys.platform,
                "python": ".".join(map(str, sys.version_info[:3])),
            }})
        elif op == "cancel":
            target = str(params.get("target", ""))
            with self._rlock:
                r = self._reqs.get(target)
            if r is not None:
                r.cancelled.set()
            self.emit({"id": rid, "event": "done", "result": {"cancelled": r is not None}})
        elif op == "shutdown":
            # Do the work first, acknowledge second: the client starts its
            # SIGTERM escalation timer only when it sees this ``done``.
            self._stopping = True
            failures = self.shutdown(exit_after=False)
            self.emit({"id": rid, "event": "done",
                       "result": {"unmount_failed": failures}})

    def _run_request(self, r: _Request, handler) -> None:
        ctx = _Ctx(self, r)
        try:
            # A handler that observed the cancel token raises
            # CancelledOperation itself; one that finished has written its
            # output, so it is reported as done even if a cancel arrived in
            # the last millisecond — "cancelled" must mean "nothing written".
            result = handler(r.params, ctx)
            self.emit({"id": r.id, "event": "done", "result": result})
        except BaseException as exc:  # noqa: BLE001 — every failure becomes an event
            try:
                code, message, detail = classify_error(exc)
                self._error(r.id, code, message, detail)
            except BaseException as exc2:  # noqa: BLE001 — a request must always end
                try:
                    self.emit({"id": r.id, "event": "error", "code": "internal",
                               "message": "The helper hit an unexpected error.",
                               "detail": repr(exc2)[:500]})
                except BaseException:
                    print(f"qc-core: could not report failure of {r.id}: {exc2!r}",
                          file=sys.stderr)
        finally:
            log.info("request %s finished", r.id)
            with self._rlock:
                self._reqs.pop(r.id, None)

    def wait_idle(self, timeout: float | None = 30.0) -> None:
        """Block until every worker has finished (``None`` = no limit)."""
        with self._rlock:
            threads = [r.thread for r in self._reqs.values() if r.thread]
        # One deadline for all of them: joining each with the full timeout
        # could hold the process for N x timeout at EOF.
        deadline = None if timeout is None else time.monotonic() + timeout
        for t in threads:
            t.join(None if deadline is None else max(0.0, deadline - time.monotonic()))

    def shutdown(self, *, exit_after: bool = True) -> list[str]:
        """Cancel running work, save and unmount every volume, then exit.
        Idempotent: a second call (run()'s finally after the shutdown op,
        or a signal during shutdown) returns immediately."""
        with self._shutdown_lock:
            if self._shutdown_started:
                return []
            self._shutdown_started = True
        self._stopping = True
        with self._rlock:
            reqs = list(self._reqs.values())
        for r in reqs:
            r.cancelled.set()
        # One deadline for every worker, and the client's SIGTERM escalation
        # (ServiceStop on this thread) must not unwind past the unmount loop
        # below — that loop is the point of shutting down.
        deadline = time.monotonic() + JOIN_SECONDS
        for r in reqs:
            if r.thread and r.thread is not threading.current_thread():
                try:
                    r.thread.join(max(0.0, deadline - time.monotonic()))
                except BaseException as exc:  # noqa: BLE001
                    print(f"qc-core: shutdown join interrupted: {exc!r}", file=sys.stderr)
                    break
        failures: list[str] = []
        try:
            from quantacrypt.core.fuse_ops import (_mounted_volumes, get_mounted_volumes,
                                                   unmount_volume)
        except ImportError:  # fusepy absent — nothing to unmount
            mounts = []
        else:
            try:
                mounts = list(get_mounted_volumes())
            except BaseException:  # noqa: BLE001 — the same escalation, earlier
                mounts = list(_mounted_volumes)
        for mp in mounts:
            try:
                unmount_volume(mp)
            except Exception as exc:  # noqa: BLE001 — reported, not hidden
                failures.append(mp)
                # `qc-core: ` lines are public in the shell's log; the
                # mount point is not.
                print(f"qc-core: unmount failed: {safe_reason(exc)}", file=sys.stderr)
                log.info("unmount of %s failed: %s", mp, exc)
            except BaseException as exc:  # noqa: BLE001
                # The client's SIGTERM escalation arrives as ServiceStop
                # on this thread while one diskutil is wedged.  Letting it
                # unwind abandoned every later volume (their dirty buffers
                # with them) and the unmount_failed report; the loop has
                # to finish and the stdin loop already knows to stop.
                failures.append(mp)
                print(f"qc-core: unmount interrupted: {exc!r}", file=sys.stderr)
                log.info("unmount of %s interrupted", mp)
        if exit_after and self._exit_fn:
            self._exit_fn()
        return failures


class _Ctx:
    """What a handler gets: progress emitter + cancel predicate."""

    def __init__(self, svc: Service, req: _Request):
        self._svc = svc
        self._req = req

    def progress(self, message: str) -> None:
        stage, label, pct = stage_for(message)
        self._svc.emit({"id": self._req.id, "event": "progress", "stage": stage,
                        "label": label, "pct": pct, "message": message})

    def cancelled(self) -> bool:
        return self._req.cancelled.is_set()

    def check(self) -> None:
        if self.cancelled():
            raise cc.CancelledOperation("Cancelled")


# ── Handlers ─────────────────────────────────────────────────────────────────

def _need(params: dict, *keys: str) -> None:
    missing = [k for k in keys if not params.get(k)]
    if missing:
        raise InvalidRequest(f"Missing parameter(s): {', '.join(missing)}")
    for k in keys:
        if not isinstance(params[k], str):
            raise InvalidRequest(f"Parameter {k!r} must be a string")


def _int_pair(params: dict) -> tuple[int, int]:
    """Validated (k, n) for split-key modes."""
    k, n = params.get("k"), params.get("n")
    if (not isinstance(k, int) or not isinstance(n, int)
            or isinstance(k, bool) or isinstance(n, bool)):
        raise InvalidRequest("Split-key mode needs integer 'k' and 'n'")
    if not (2 <= k <= n <= 255):
        raise InvalidRequest("Split-key mode needs 2 <= k <= n <= 255")
    return k, n


def _opt_str(params: dict, key: str) -> str | None:
    v = params.get(key)
    if v is not None and not isinstance(v, str):
        raise InvalidRequest(f"Parameter {key!r} must be a string")
    return v


def _opt_list(params: dict, key: str) -> list | None:
    v = params.get(key)
    if v is not None and not isinstance(v, list):
        raise InvalidRequest(f"Parameter {key!r} must be a list")
    return v


def op_fuse_check(params: dict, ctx: _Ctx) -> dict:
    try:
        from quantacrypt.core.fuse_ops import check_fuse_components
        comps = check_fuse_components()
    except Exception as exc:  # noqa: BLE001 — report, don't crash the service
        comps = {"fusepy": {"ok": False, "detail": str(exc)},
                 "fuse_backend": {"ok": False, "detail": "not checked"}}
    return {**comps, "ok": all(c.get("ok") for c in comps.values())}


def op_inspect(params: dict, ctx: _Ctx) -> dict:
    _need(params, "path")
    return pkg.inspect_summary(os.path.expanduser(params["path"]))


def op_encrypt(params: dict, ctx: _Ctx) -> dict:
    _need(params, "source", "output", "mode")
    mode = params["mode"]
    if mode not in ("password", "single", "shamir"):
        raise InvalidRequest(f"Unknown mode {mode!r}")
    k = n = None
    if mode == "shamir":
        k, n = _int_pair(params)
    else:
        _need(params, "password")
    _embed = _opt_str(params, "embed_binary")
    return pkg.encrypt_to_qcx(
        os.path.expanduser(params["source"]), os.path.expanduser(params["output"]),
        mode=mode, password=_opt_str(params, "password"), k=k, n=n,
        progress=ctx.progress, cancel_check=ctx.cancelled,
        embed_binary=os.path.expanduser(_embed) if _embed else None)


def op_decrypt(params: dict, ctx: _Ctx) -> dict:
    _need(params, "path")
    verify_only = bool(params.get("verify_only"))
    if not verify_only:
        _need(params, "output_dir")
    _outdir = _opt_str(params, "output_dir") or ""
    return pkg.decrypt_qcx(
        os.path.expanduser(params["path"]),
        os.path.expanduser(_outdir) if _outdir else "",
        password=_opt_str(params, "password"), shares=_opt_list(params, "shares"),
        verify_only=verify_only, progress=ctx.progress, cancel_check=ctx.cancelled)


def op_volume_inspect(params: dict, ctx: _Ctx) -> dict:
    """What can be said about a .qcv without any credential — lets the
    client pick password vs split-key entry before asking."""
    from quantacrypt.core import volume as vol
    _need(params, "path")
    path = os.path.expanduser(params["path"])
    header, auth = vol.read_volume_auth_params(path)
    mode = auth["mode"]          # required by _read_auth_params
    return {
        "path": path,
        "size": os.path.getsize(path),
        # read_header() returns "version"; "format_version" was never a
        # key, so this field was structurally always null.
        "format_version": header.get("version"),
        "mode": mode,
        "threshold": auth.get("threshold"),
        "total": auth.get("total"),
    }


def op_volume_create(params: dict, ctx: _Ctx) -> dict:
    from quantacrypt.core import volume as vol
    _need(params, "path", "mode")
    path = os.path.expanduser(params["path"])
    if not path.lower().endswith(".qcv"):
        path += ".qcv"
    if os.path.exists(path):
        raise FileExistsError(errno_EEXIST, "already exists", path)
    mode = params["mode"]
    if mode not in ("password", "single", "shamir"):
        raise InvalidRequest(f"Unknown mode {mode!r}")
    try:
        if mode != "shamir":
            _need(params, "password")
            vol.create_volume_single(path, params["password"], progress_cb=ctx.progress,
                                     cancel_check=ctx.cancelled)
            return {"path": path, "mode": "single", "shares": []}
        k, n = _int_pair(params)
        _meta, shares = vol.create_volume_shamir(path, n, k, progress_cb=ctx.progress,
                                                 cancel_check=ctx.cancelled)
        return {"path": path, "mode": "shamir", "threshold": k, "total": n,
                "shares": pkg.shares_with_mnemonics(shares, k)}
    except cc.CancelledOperation:
        # "cancelled" must mean "nothing written": a container written
        # before the cancel was observed is removed (the Tk manager does
        # the same), because its shares/password would never be shown.
        try:
            os.remove(path)
        except OSError:
            pass
        raise


def op_volume_mount(params: dict, ctx: _Ctx) -> dict:
    from quantacrypt.core import volume as vol
    from quantacrypt.core.fuse_ops import mount_volume
    _need(params, "path", "mount_point")
    # Both expanded: mount_volume realpath()s the container (which does not
    # expand `~`), and the mount point must round-trip into volume_unmount
    # and volume_list.  Every path param expands `~` (protocol doc).
    path, mp = os.path.expanduser(params["path"]), os.path.expanduser(params["mount_point"])
    ctx.progress("Reading volume...")
    _header, auth = vol.read_volume_auth_params(path)
    ctx.check()
    if auth["mode"] == "single":   # required by _read_auth_params
        _need(params, "password")
        ctx.progress("Deriving 512-bit password key (Argon2id)...")
        key = vol.derive_volume_key_single(params["password"], auth)
    else:
        codes = pkg.normalize_shares(_opt_list(params, "shares") or [])
        k = auth.get("threshold") or len(codes)
        if len(codes) < k:
            raise InvalidInput(f"Need {k} different shares to unlock this volume, got {len(codes)}")
        ctx.progress(f"Combining {k} shares to recover the key...")
        key = vol.derive_volume_key_shamir(codes[:k], auth)
    ctx.check()
    ctx.progress("Mounting...")
    fuse_obj = mount_volume(path, key, mp, credential_proven=True)
    vc = getattr(fuse_obj, "volume", None)
    suspicious = bool(getattr(vc, "journal_suspicious", False))
    # Name the preserved tail to the caller. open() copies it to a sidecar
    # beside the volume before the next save overwrites it, but evidence
    # nobody is told about is indistinguishable from litter — the user finds
    # an unexplained file next to their vault and deletes it.
    sidecar = getattr(vc, "suspect_sidecar", None) if suspicious else None
    return {"mount_point": mp, "volume_path": path,
            "journal_suspicious": suspicious, "suspect_sidecar": sidecar,
            # The container or its folder refuses writes: the drive is
            # served read-only and the UI should say so.
            "read_only": bool(getattr(vc, "read_only", False))}


def op_volume_unmount(params: dict, ctx: _Ctx) -> dict:
    from quantacrypt.core.fuse_ops import unmount_volume
    _need(params, "mount_point")
    mp = os.path.expanduser(params["mount_point"])
    unmount_volume(mp)
    return {"mount_point": mp}


def op_volume_list(params: dict, ctx: _Ctx) -> dict:
    try:
        from quantacrypt.core.fuse_ops import get_mounted_volumes
        mounted = get_mounted_volumes()
    except Exception:  # fusepy absent
        mounted = {}
    out = []
    for mp, info in mounted.items():
        # read_only travels with every list entry, not only the mount result:
        # the shell replaces its mounted list from this poll every few
        # seconds, so a flag carried only by volume_mount would vanish.
        entry = {"mount_point": mp, "volume_path": info.get("volume_path"),
                 "read_only": bool(info.get("read_only", False))}
        vc = info.get("volume")
        try:
            entry["stats"] = vc.stat() if vc is not None else None
        except Exception:  # noqa: BLE001 — stats are best-effort
            entry["stats"] = None
        out.append(entry)
    return {"volumes": out}
