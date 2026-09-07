"""User-facing error text and machine-readable error codes.

Lives in core (not ui) so the service and every front end share one
vocabulary.  ``friendly_error`` returns the sentence a person should read;
``classify_error`` adds the code a program should branch on.
"""

from __future__ import annotations

import errno as _errno
import os


class InvalidRequest(ValueError):
    """The CLIENT sent a malformed request (missing/ill-typed parameter).
    Maps to ``invalid_request``; a UI should treat that as its own bug."""


class InvalidInput(ValueError):
    """The USER supplied something unusable — a share that does not parse,
    too few shares, a missing password, an output inside its own source.
    Maps to ``invalid_input``; the message is written for the user."""


class CorruptPayload(ValueError):
    """The credentials were proven (envelope decrypted, HMAC verified) but the
    payload failed authentication: bit-rot, truncation or tampering.  Must
    never be reported as a wrong password."""


def friendly_error(exc: BaseException) -> str:
    """Translate a raw exception into a user-facing, actionable message.

    Known shapes are mapped to plain English with a next step; anything else
    falls back to ``str(exc)`` (or the type name when the message is empty —
    cryptography's ``InvalidTag`` stringifies to "").
    """
    if isinstance(exc, (InvalidRequest, InvalidInput, CorruptPayload)):
        return str(exc)
    if isinstance(exc, FileNotFoundError):
        return "File not found. It may have been moved or deleted."
    if isinstance(exc, FileExistsError):
        name = exc.filename or str(exc)
        return f"{name} already exists. Choose a different name."
    if isinstance(exc, KeyError):
        return (f"The file is missing the field {exc.args[0]!r}, so it may be corrupt "
                "or from an unsupported version.")
    if isinstance(exc, PermissionError):
        return ("Access denied. Check you have permission to read / write "
                "this file, and that it isn't open in another app.")
    if isinstance(exc, IsADirectoryError):
        return "That path is a folder, not a file."
    if isinstance(exc, OSError):
        if exc.errno == _errno.ENOSPC:
            return "Disk is full. Free up space and try again."
        if exc.errno == _errno.EIO:
            return "Disk read / write error: the drive may be failing."
        if exc.errno == _errno.EROFS:
            return "Destination is read-only."

    msg = str(exc)
    lower = (msg or type(exc).__name__).lower()
    if "invalidtag" in lower or "authentication" in lower:
        return ("The password or shares are incorrect, or the file has been "
                "modified since it was encrypted.")
    # Before the version branches: every writer stores the HMAC, so a
    # message about it is about integrity even if it also mentions versions.
    if "hmac" in lower:
        return ("The file's integrity check failed. It may be "
                "corrupt or tampered with.")
    if "unsupported" in lower and "version" in lower:
        return ("This file was created with a newer version of QuantaCrypt. "
                "Please update the app.")
    if "older" in lower and "version" in lower:
        return ("This file uses an older format. Decrypt it with the "
                "original app version, then re-encrypt with this one.")
    if "truncat" in lower or "appears truncated" in lower:
        return ("The file appears to be truncated or incomplete. "
                "Re-download or restore from backup.")
    if not msg:
        return f"{type(exc).__name__} (no additional detail)"
    return msg


def safe_reason(exc: BaseException) -> str:
    """One line for a log record that may be published, naming no path.

    The Swift shell makes the helper's ERROR-level stderr public in the
    unified log, and ``str(OSError)`` carries ``filename`` — the container
    or the mount point.  An ERROR line therefore quotes errno and strerror
    only; the path belongs on a paired INFO line, which stays private.
    """
    if isinstance(exc, OSError) and exc.errno is not None:
        # The canonical text for the errno, never the exception's own
        # strerror: volume.py builds OSErrors whose message names a vpath.
        return f"{type(exc).__name__}: [Errno {exc.errno}] {os.strerror(exc.errno)}"
    return type(exc).__name__


def classify_error(exc: BaseException) -> tuple[str, str, str]:
    """Return ``(code, message, detail)`` for an exception.

    Codes: wrong_credentials, cancelled, invalid_request, invalid_input,
    not_found, already_exists, permission_denied, io, format, unsupported,
    busy, internal.
    """
    from quantacrypt.core.crypto import CancelledOperation

    detail = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    message = friendly_error(exc)
    if isinstance(exc, CancelledOperation):
        return "cancelled", "Cancelled. Nothing was written.", detail
    if isinstance(exc, InvalidRequest):
        return "invalid_request", message, detail
    if isinstance(exc, InvalidInput):
        return "invalid_input", message, detail
    if isinstance(exc, CorruptPayload):
        return "format", message, detail
    if isinstance(exc, FileNotFoundError):
        return "not_found", message, detail
    if isinstance(exc, FileExistsError):
        return "already_exists", message, detail
    if isinstance(exc, PermissionError):
        return "permission_denied", message, detail
    if isinstance(exc, OSError):
        return "io", message, detail
    if isinstance(exc, KeyError):
        return "format", message, detail
    lower = (str(exc) or type(exc).__name__).lower()
    if "invalidtag" in lower or "authentication" in lower or "incorrect" in lower:
        return "wrong_credentials", message, detail
    if ("already mounted" in lower or "in use" in lower or "busy" in lower
            or "another process" in lower):
        return "busy", message, detail
    if "hmac" in lower:
        return "format", message, detail
    if "version" in lower and ("newer" in lower or "older" in lower or "unsupported" in lower):
        return "unsupported", message, detail
    if isinstance(exc, ValueError):
        return "format", message, detail
    if isinstance(exc, (NotImplementedError, RuntimeError)) and (
            "fusepy" in lower or "backend" in lower or "not available" in lower
            or "not installed" in lower):
        return "unsupported", message, detail
    if isinstance(exc, RuntimeError) and "mount" in lower:
        return "io", message, detail
    return "internal", message, detail
