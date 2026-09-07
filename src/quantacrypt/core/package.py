"""High-level .qcx operations shared by every front end.

Everything here is UI-agnostic: paths in, paths out, progress as strings,
cancellation as a predicate.  The Tk wizards and the ``qc-core`` service
both build on these so key derivation, output naming, and folder staging
exist exactly once.
"""

from __future__ import annotations

import base64 as _b64
import json
import os
import stat
import ctypes
import struct
import sys
import tempfile
import time
import zipfile
import zlib
from typing import Callable, Iterable

from quantacrypt.core import crypto as cc
from quantacrypt.core.crypto import (
    MAGIC, MIN_FORMAT_VERSION, MAX_FORMAT_VERSION, CancelledOperation,
)
from quantacrypt.core.errors import CorruptPayload, InvalidInput, InvalidRequest
from quantacrypt.core.volume import _fsync_dir

Progress = Callable[[str], None] | None
CancelCheck = Callable[[], bool] | None

_MAX_TAIL = 1 << 20  # 1 MB tail search window for the metadata envelope


# ── Parsing ───────────────────────────────────────────────────────────────────

def _is_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _field_bytes(meta: dict, key: str) -> bytes:
    """Base64-decode a metadata field, reporting a wrong type as a format
    error rather than the TypeError b64decode raises for a list or a number."""
    v = meta[key]
    if not isinstance(v, str):
        raise ValueError(f"File metadata field {key!r} is not text; the file may be corrupt")
    try:
        return _b64.b64decode(v, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"File metadata field {key!r} is not valid; the file may be corrupt") from exc


def load_pkg(path: str) -> dict:
    """Parse a .qcx file's metadata envelope without reading the payload.

    Raises ``ValueError`` with a user-readable reason for anything that is
    not a supported QuantaCrypt file.  The envelope is attacker-controlled
    cleartext, so every field the decrypt path does arithmetic on is
    type-checked here: a string ``version`` or a float ``threshold`` used to
    surface as a TypeError, which the helper reports as an internal error
    and the argv launcher swallowed.
    """
    file_size = os.path.getsize(path)
    tail_size = min(file_size, _MAX_TAIL)
    with open(path, "rb") as f:
        f.seek(file_size - tail_size)
        tail = f.read(tail_size)
    i = tail.rfind(MAGIC)
    if i < 0:
        raise ValueError("Not a QuantaCrypt file")
    o = i + len(MAGIC)
    if o + 4 > len(tail):
        raise ValueError("File appears truncated or corrupt")
    n = struct.unpack(">I", tail[o:o + 4])[0]
    if o + 4 + n > len(tail):
        raise ValueError("File appears truncated or corrupt")
    try:
        pkg = json.loads(tail[o + 4:o + 4 + n])
    except (ValueError, RecursionError) as exc:
        raise ValueError("File metadata is not valid JSON; the file may be corrupt") from exc
    if not isinstance(pkg, dict):
        raise ValueError("File metadata envelope is not a valid dictionary; the file may be corrupt")
    meta = pkg.get("meta", {})
    if not isinstance(meta, dict):
        raise ValueError("File metadata is not a valid dictionary; the file may be corrupt")
    ver = meta.get("version", 1)
    if not _is_int(ver):
        raise ValueError("File format version is not a number; the file may be corrupt")
    if ver > MAX_FORMAT_VERSION:
        raise ValueError(
            f"This file was created with a newer version of QuantaCrypt (format v{ver}). "
            f"Please upgrade the app."
        )
    if ver < MIN_FORMAT_VERSION:
        raise ValueError(
            f"This file uses an older format (v{ver}) that is no longer supported. "
            f"Use an older version of QuantaCrypt to decrypt it, "
            f"then re-encrypt with this version."
        )
    if "mode" not in meta:
        raise ValueError("File metadata is missing required field 'mode'; the file may be corrupt")
    if meta["mode"] not in ("single", "shamir"):
        raise ValueError(f"Unknown encryption mode {meta['mode']!r}. The file may be corrupt or from an unsupported version")
    if meta["mode"] == "shamir":
        for field in ("threshold", "total"):
            if field not in meta:
                raise ValueError(f"Shamir file metadata is missing required field '{field}'; the file may be corrupt")
            if not _is_int(meta[field]):
                raise ValueError(f"Shamir file metadata field '{field}' is not a number; the file may be corrupt")
        if not (2 <= meta["threshold"] <= meta["total"] <= 255):
            raise ValueError(f"Invalid Shamir parameters: threshold={meta.get('threshold')}, total={meta.get('total')}")
    for field in ("payload_chunk_count", "payload_offset", "chunk_size"):
        if field in meta and (not _is_int(meta[field]) or meta[field] < 0):
            raise ValueError(f"File metadata field '{field}' is not a valid count; the file may be corrupt")
    # Format 2 names its KEM and (password mode) its Argon2 parameters;
    # both are validated before anything is derived from them.
    if ver >= 2:
        if "kem" not in meta:
            raise ValueError("File metadata does not name its key encapsulation; the file may be corrupt")
        if meta["mode"] == "single" and "argon2" not in meta:
            raise ValueError("File metadata does not record its password-hardening parameters; the file may be corrupt")
    if "kem" in meta:
        cc.validate_kem(meta["kem"])
    if "argon2" in meta:
        cc.validate_argon2_params(meta["argon2"])
    return pkg


def inspect_summary(path: str) -> dict:
    """What can be said about a .qcx without any credential."""
    meta = load_pkg(path)["meta"]
    return {
        "path": path,
        "size": os.path.getsize(path),
        "version": meta.get("version", 1),
        "mode": meta["mode"],
        "threshold": meta.get("threshold"),
        "total": meta.get("total"),
        "embedded": bool(meta.get("payload_offset")),
        "argon2": "argon_salt" in meta,
    }


# ── Shares ───────────────────────────────────────────────────────────────────

def normalize_shares(shares: Iterable[str]) -> list[str]:
    """Accept QCSHARE- codes or 50-word mnemonics (mixed), return codes,
    de-duplicated, in input order.  Raises ``ValueError`` on an unreadable
    share so the caller can name which one."""
    codes: list[str] = []
    seen: set[str] = set()
    for i, raw in enumerate(shares, 1):
        s = (raw or "").strip()
        if not s:
            continue
        try:
            if s.upper().startswith("QCSHARE-"):
                code = cc.encode_share(cc.decode_share(s))
            else:
                code = cc.encode_share(cc.mnemonic_to_share(" ".join(s.split())))
        except Exception as exc:
            raise InvalidInput(f"Share {i} can't be read: {exc}") from exc
        if code in seen:
            continue
        seen.add(code)
        codes.append(code)
    return codes


def _phrases_in_run(words: list[str]) -> list[str]:
    """The share codes hidden in one run of BIP-39 words, in order.

    Three passes, cheapest and safest first.  The 8-bit checksum false-
    accepts 1 window in 256, and a false accept that overlaps a real phrase
    would swallow it, so the passes that try one alignment per segment come
    before the one that tries every alignment:
      1. segments aligned to the END of the run (header + phrases);
      2. segments aligned to the START (phrases + trailer prose);
      3. only if neither found anything, every offset left to right
         (header + phrases + trailer).
    A false accept that survives produces a share shamir_recover / the HMAC
    then reject."""
    n = cc.MNEMONIC_WORDS_PER_SHARE
    if len(words) < n:
        return []

    def decode(seg: list[str]) -> str | None:
        try:
            return cc.encode_share(cc.mnemonic_to_share(" ".join(seg)))
        except Exception:
            return None

    # Each pass hands the part of the run it did not consume back to the
    # same function: "share one / <phrase> / share two / <phrase>" — every
    # word of it in the wordlist — used to keep only the last phrase.
    tail: list[str] = []
    end = len(words)
    while end >= n and (code := decode(words[end - n:end])):
        tail.append(code); end -= n
    if tail:
        tail.reverse()
        return _phrases_in_run(words[:end]) + tail
    head: list[str] = []
    start = 0
    while start + n <= len(words) and (code := decode(words[start:start + n])):
        head.append(code); start += n
    if head:
        return head + _phrases_in_run(words[start:])
    found: list[str] = []
    i = 0
    while i + n <= len(words):
        code = decode(words[i:i + n])
        if code:
            found.append(code); i += n
        else:
            i += 1
    return found


def extract_share_codes(text: str) -> list[str]:
    """Find every share in free text (share files, pasted notes) as QCSHARE-
    codes, in order of appearance.  Tolerates headers and prose: QCSHARE-
    lines are taken as-is; runs of lines made only of BIP-39 words are
    gathered and split into 50-word phrases by checksum (see
    ``_phrases_in_run``), so two phrases separated by a single newline, or
    wrapped 8 per line with no blank line between, are two shares.
    Duplicates collapse.  Used by both UIs so "Load from file…" and "Paste
    all" agree."""
    codes: list[str] = []
    seen: set[str] = set()
    try:
        wl_set = set(cc._load_wordlist())
    except Exception:  # wordlist unavailable — codes only
        wl_set = set()
    block: list[str] = []

    def add(code: str) -> None:
        if code not in seen:
            seen.add(code); codes.append(code)

    def flush() -> None:
        if block and wl_set:
            for code in _phrases_in_run(block):
                add(code)
        block.clear()

    for ln in (text or "").splitlines():
        ln = ln.strip()
        if ln.upper().startswith("QCSHARE-"):
            flush()                      # a code ends any phrase run
            try:
                add(cc.encode_share(cc.decode_share(ln)))
            except Exception:
                continue
            continue
        toks = ln.lower().split()
        if wl_set and toks and all(t in wl_set for t in toks):
            block.extend(toks)
        else:
            flush()
    flush()
    return codes


def shares_with_mnemonics(shares: list[str], k: int) -> list[dict]:
    """Pair each share code with its mnemonic for display / saving."""
    out = []
    for i, s in enumerate(shares, 1):
        out.append({
            "index": i,
            "code": s,
            "mnemonic": cc.share_to_mnemonic({**cc.decode_share(s), "threshold": k}),
        })
    return out


# ── Key derivation ───────────────────────────────────────────────────────────

def derive_final_key(meta: dict, *, password: str | None = None,
                     shares: Iterable[str] | None = None,
                     progress: Progress = None,
                     cancel_check: CancelCheck = None) -> tuple[bytes, bytes]:
    """Return ``(final_key, hmac_key)`` for a .qcx metadata dict.

    Single mode needs ``password``; Shamir mode needs at least ``threshold``
    distinct ``shares`` (codes or mnemonics).  Verifies the metadata HMAC
    before returning, so a wrong credential surfaces here.
    """
    def _p(m):
        if progress:
            progress(m)

    def _check():
        if cancel_check and cancel_check():
            raise CancelledOperation("Cancelled")

    def d64(k):
        return _field_bytes(meta, k)

    # Format 1 carries neither field: the legacy KEM and the shipped Argon2
    # parameters are implied.  Format 2 names both, validated by load_pkg.
    kem = cc.validate_kem(meta.get("kem"))
    argon2 = meta.get("argon2")

    if meta["mode"] == "single":
        if not password:
            raise InvalidInput("A password is required to open this file")
        _p("Deriving 512-bit password key (Argon2id)...")
        pw_bytes = password.encode()
        argon_key = cc.argon2id_derive(pw_bytes, d64("argon_salt"), argon2)
        del pw_bytes
        _check()
        _p("Decrypting Kyber private key...")
        sk = cc.aes_gcm_decrypt(argon_key, d64("kyber_sk_enc_nonce"), d64("kyber_sk_enc"))
        _check()
        _p("Decapsulating shared secret...")
        kem_ss = _decaps_proven(sk, d64("kyber_kem_ct"), kem)
        final_key = cc.xor_bytes(argon_key, kem_ss)
        hmac_key = final_key
    else:
        k = meta["threshold"]
        codes = normalize_shares(shares or [])
        if len(codes) < k:
            raise InvalidInput(
                f"Need {k} different shares to open this file, got {len(codes)}")
        _p(f"Combining {k} shares to recover the key...")
        share_dicts = [cc.decode_share(s) for s in codes[:k]]
        master_key = cc.shamir_recover(share_dicts)
        _check()
        _p("Decrypting Kyber private key...")
        sk = cc.aes_gcm_decrypt(master_key, d64("kyber_sk_enc_nonce"), d64("kyber_sk_enc"))
        _check()
        _p("Decapsulating shared secret...")
        kem_ss = _decaps_proven(sk, d64("kyber_kem_ct"), kem)
        final_key = cc.xor_bytes(master_key, kem_ss)
        hmac_key = master_key
    _check()
    try:
        cc._verify_meta_hmac(hmac_key, meta)
    except ValueError as exc:
        # The envelope unsealed, so the password/shares are right.  A
        # metadata HMAC that fails now means a field was edited after
        # encryption — a version rolled back, the KEM name swapped — and
        # reporting that as a wrong password (with the Caps-Lock advice and
        # "no way to recover" copy) told the wrong story.
        raise CorruptPayload(
            "The password or shares are right, but this file's metadata was "
            "tampered with or damaged after it was encrypted. It cannot be "
            "opened; use another copy or a backup.") from exc
    return final_key, hmac_key


def _decaps_proven(sk: bytes, kem_ct: bytes, kem: str) -> bytes:
    """Decapsulate after the KEM private key has unsealed.

    Unsealing ``kyber_sk_enc`` is the credential proof; a failure past it —
    a ciphertext of the wrong length, the other KEM's name — is tampering
    or damage, never a wrong password.
    """
    try:
        return cc.kyber_decaps(sk, kem_ct, kem)
    except Exception as exc:
        raise CorruptPayload(
            "The password or shares are right, but this file's key data was "
            "tampered with or damaged after it was encrypted. It cannot be "
            "opened; use another copy or a backup.") from exc


def verify_first_chunk(qcx_path: str, meta: dict, final_key: bytes) -> None:
    """Decrypt chunk 0 only — proves the key without writing any output.
    Raises on a wrong key or a corrupt/truncated payload."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # The filename envelope is always present and encrypted under the same
    # key, so it proves the key even for a 0-byte payload (which has no
    # chunk to decrypt).
    cc.aes_gcm_decrypt(final_key, _b64.b64decode(meta["filename_nonce"]),
                       _b64.b64decode(meta["filename_enc"]))
    if meta.get("payload_chunk_count", 0) == 0:
        return
    payload_offset = meta.get("payload_offset", 0)
    base_nonce = _b64.b64decode(meta["payload_nonce"])
    cipher = AESGCM(cc.derive_aes_key(final_key))
    with open(qcx_path, "rb") as f:
        f.seek(payload_offset)
        seq_raw = f.read(4)
        if len(seq_raw) < 4:
            raise ValueError("File appears truncated")
        seq = struct.unpack(">I", seq_raw)[0]
        if seq != 0:
            raise ValueError(f"First chunk has unexpected sequence number {seq}. The file may be corrupt")
        len_raw = f.read(4)
        if len(len_raw) < 4:
            raise ValueError("File appears truncated")
        ct_len = struct.unpack(">I", len_raw)[0]
        if ct_len > cc.CHUNK_SIZE + 16:
            raise ValueError(
                f"Chunk declares an implausible size ({ct_len} bytes). The file may be corrupt")
        ct = f.read(ct_len)
    nonce = cc._chunk_nonce(base_nonce, 0)
    aad = cc._chunk_aad(0, meta["payload_chunk_count"] == 1)
    try:
        cipher.decrypt(nonce, ct, aad)
    except Exception as exc:  # InvalidTag: the key is proven, so the data is bad
        raise CorruptPayload(
            "The file's contents are damaged or were altered after encryption. "
            "The password is right, but this copy can't be restored. Try another "
            "copy or a backup.") from exc


# ── Output naming ─────────────────────────────────────────────────────────────

def safe_output_name(fname: str | None) -> str:
    """Original filename from the payload → a name safe to create.
    basename() blocks traversal; control characters and NULs are dropped;
    an empty result becomes 'decrypted'."""
    name = os.path.basename(fname or "")
    name = "".join(ch for ch in name if ch.isprintable() and ch not in ("/", "\0"))
    name = name.strip()
    # Keep a leading dot (hidden files like .env are legitimate names); only
    # the bare "." / ".." entries and trailing dots are dropped.
    name = name.rstrip(".")
    if name.strip(".") == "":
        name = ""
    return name or "decrypted"


def unique_path(out_dir: str, name: str) -> tuple[str, bool]:
    """``(path, renamed)`` — never overwrite: report.pdf → report_2.pdf."""
    out = os.path.join(out_dir, name)
    root, ext = os.path.splitext(name)
    n = 2
    while os.path.exists(out):
        out = os.path.join(out_dir, f"{root}_{n}{ext}")
        n += 1
    return out, n > 2


#: LSFileQuarantineType flags. 0x0081 = "downloaded, never opened" — the
#: same shape Safari and Mail set, which is what makes Gatekeeper assess the
#: file on first open.
_QUARANTINE_FLAGS = "0081"


def _mark_quarantined(path: str) -> None:
    """Attach com.apple.quarantine to freshly decrypted output.

    A .qcx is a transport container for someone else's content. Because
    QuantaCrypt writes the plaintext itself, LaunchServices sees a locally
    authored file — no quarantine, no Gatekeeper assessment — and both UIs
    put an "Open file" button on the success card. A folder-sourced .qcx
    decrypts to a .zip whose extracted .app would then run unchecked, and
    .terminal/.webloc/.inetloc need no execute bit at all.

    Note os.setxattr does not exist on macOS CPython, so this goes through
    libc directly. Best-effort: never fail a completed decrypt over it.
    """
    if sys.platform != "darwin":
        return
    stamp = format(int(time.time()), "x")
    value = f"{_QUARANTINE_FLAGS};{stamp};QuantaCrypt;".encode()
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        setxattr = libc.setxattr
        # Declared, not inferred: without argtypes ctypes passes the size_t
        # as a C int and the call only works because libffi happens to
        # sign-extend it on arm64.
        setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                             ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
        setxattr.restype = ctypes.c_int
        setxattr(os.fsencode(path), b"com.apple.quarantine", value, len(value), 0, 0)
    except (OSError, AttributeError, ValueError, TypeError):
        pass


def _place_without_clobber(tmp: str, out_dir: str, name: str) -> tuple[str, bool]:
    """Move ``tmp`` to a fresh name in ``out_dir`` atomically: ``os.link``
    fails with EEXIST instead of replacing, so a file that appears between
    the existence check and the rename is never overwritten.  Falls back to
    ``os.replace`` on filesystems without hard links (exFAT, some SMB)."""
    renamed = False
    root, ext = os.path.splitext(name)
    n = 1
    while True:
        cand = os.path.join(out_dir, name if n == 1 else f"{root}_{n}{ext}")
        try:
            os.link(tmp, cand)
        except FileExistsError:
            n += 1; renamed = True
            continue
        except OSError:
            cand, renamed = unique_path(out_dir, name)
            os.replace(tmp, cand)
            return cand, renamed
        os.unlink(tmp)
        return cand, renamed


def batch_output_paths(paths: list[str], out_dir: str) -> list[str]:
    """Map each batch input to a UNIQUE <stem>.qcx in out_dir.

    Inputs with colliding stems (report.txt + report.md) must not map to
    the same output — the second os.replace would silently destroy the
    first file's ciphertext while both show as succeeded.
    """
    outs, used = [], set()
    for p in paths:
        stem = os.path.splitext(os.path.basename(p))[0]
        cand, i = stem, 2
        while (cand + ".qcx").lower() in used:
            cand = f"{stem}_{i}"
            i += 1
        used.add((cand + ".qcx").lower())
        outs.append(os.path.join(out_dir, cand + ".qcx"))
    return outs


# ── Folders ───────────────────────────────────────────────────────────────────

def folder_stats(folder: str) -> tuple[int, int]:
    """Return (file_count, total_bytes) for a folder tree.

    Symlinks are excluded because zip_folder() does not archive them; the
    two have to agree or the progress line never reaches 100%.
    """
    count, total = 0, 0
    for dirpath, _, filenames in os.walk(folder):
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if not _is_regular(full):
                continue
            try:
                total += os.path.getsize(full)
            except OSError:
                pass
            count += 1
    return count, total


def _is_regular(path: str) -> bool:
    """True for a plain file.  Symlinks are skipped for the reason given in
    zip_folder; FIFOs and sockets because os.walk lists them as files and
    opening a FIFO blocks until a writer appears — never — with the cancel
    token never consulted, while a socket fails the whole encrypt with an
    opaque errno.  Postgres and Redis sockets, Jupyter runtime dirs and
    mkfifo pipes all live inside folders people archive."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


#: Members below this size are always deflated: the sample would be the whole
#: file and zip headers dominate anyway.
_ZIP_SAMPLE_MIN = 4096
_ZIP_SAMPLE = 64 << 10


def _compress_type(path: str) -> int:
    """Deflate members that compress, store the ones that do not.

    zlib level 6 on already-compressed data (photos, video, archives, most
    office documents) gains nothing and ran at 30–80 MB/s, which made it the
    bottleneck of folder encryption.  A 64 KiB sample through level 1 is a
    cheap, reliable predictor: if it saves less than 5 % the member is stored.
    """
    try:
        if os.path.getsize(path) < _ZIP_SAMPLE_MIN:
            return zipfile.ZIP_DEFLATED
        with open(path, "rb") as f:
            sample = f.read(_ZIP_SAMPLE)
    except OSError:
        return zipfile.ZIP_DEFLATED
    if len(zlib.compress(sample, 1)) > len(sample) * 0.95:
        return zipfile.ZIP_STORED
    return zipfile.ZIP_DEFLATED


def zip_folder(folder: str, dst, progress_cb: Progress = None,
               cancel_check: CancelCheck = None, *,
               skip_path: str | None = None) -> list[str]:
    """Zip folder into *dst* — a path, or a binary sink with ``write()`` —
    with paths relative to folder's parent so the top-level directory name
    survives inside the archive.  The archive being written (or *skip_path*,
    for a sink) is skipped if the walk reaches it (output inside source).

    Given a sink with no ``seek``, zipfile writes data descriptors instead
    of seeking back to patch each local header, which is what lets
    ``encrypt_to_qcx`` archive a folder straight into the cipher with no
    plaintext staging file on disk.

    Returns the folder-relative paths of the symlinks that were skipped.

    Symlinks are never followed.  A .qcx is made to be handed to someone
    else, and ``zipfile.write()`` stores the *target's* bytes: a convenience
    link to ``~/.ssh/id_ed25519`` or a shared credentials file sitting inside
    the folder would otherwise ship inside the container with nothing saying
    so.  ``zip(1)`` and ``tar(1)`` store links as links; zipfile cannot
    without teaching every extractor to recreate them safely, so they are
    left out and reported instead.

    A directory entry is written for every real directory so that empty
    folders survive the round trip.
    """
    parent = os.path.dirname(os.path.abspath(folder))
    if isinstance(dst, (str, bytes, os.PathLike)):
        dst_abs = os.path.abspath(dst)
    else:
        dst_abs = os.path.abspath(skip_path) if skip_path else None
    total_files, _ = folder_stats(folder)
    done = 0
    skipped: list[str] = []
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for dirpath, dirnames, filenames in os.walk(folder):
            dirnames.sort()
            filenames.sort()
            # os.walk does not descend into symlinked directories, so prune
            # them from dirnames too: recording the name without its contents
            # would put an empty directory in the archive where a link was.
            for d in list(dirnames):
                if os.path.islink(os.path.join(dirpath, d)):
                    dirnames.remove(d)
                    skipped.append(os.path.relpath(os.path.join(dirpath, d), folder))
            if cancel_check and cancel_check():
                raise CancelledOperation("Compression cancelled")
            zf.write(dirpath, os.path.relpath(dirpath, parent))
            for fn in filenames:
                if cancel_check and cancel_check():
                    raise CancelledOperation("Compression cancelled")
                full = os.path.join(dirpath, fn)
                if os.path.abspath(full) == dst_abs:
                    continue
                if not _is_regular(full):
                    skipped.append(os.path.relpath(full, folder))
                    continue
                zf.write(full, os.path.relpath(full, parent),
                         compress_type=_compress_type(full))
                done += 1
                if progress_cb and total_files:
                    pct = done / total_files
                    progress_cb(f"Compressing folder… {int(pct * 100)}% ({done}/{total_files} files)")
    if skipped and progress_cb:
        progress_cb(
            f"Skipped {len(skipped)} item{'' if len(skipped) == 1 else 's'} "
            "(symbolic links and special files). Links are not followed, so "
            "their targets stay out of the archive."
        )
    return skipped


# ── Encrypt / decrypt ─────────────────────────────────────────────────────────

def encrypt_to_qcx(source: str, output: str, *, mode: str,
                   password: str | None = None, k: int | None = None,
                   n: int | None = None, progress: Progress = None,
                   cancel_check: CancelCheck = None,
                   embed_binary: str | None = None) -> dict:
    """Encrypt a file or folder to ``output`` (.qcx).  Atomic: writes to a
    0600 temp beside the output and renames.  A folder is archived straight
    into the cipher — no plaintext staging file ever touches the disk, and
    the transient space needed is the ciphertext alone.  Returns a JSON-able
    summary."""
    if mode not in ("password", "single", "shamir"):
        raise InvalidRequest(f"Unknown mode {mode!r}")
    single = mode in ("password", "single")
    if single and not password:
        raise InvalidInput("A password is required")
    if single:
        # The floor lives here so both front ends inherit it: the SwiftUI
        # shell enforced 8 characters, the Tk UI enforced nothing, and Tk
        # batch mode skipped even the soft warning.
        cc.reject_weak_secret(password)      # raises InvalidInput
    if not single and not (k and n and 2 <= k <= n <= 255):
        raise InvalidRequest("Split-key mode needs 2 <= k <= n <= 255")
    if not os.path.exists(source):
        raise FileNotFoundError(source)
    out_abs = os.path.abspath(output)
    src_abs = os.path.abspath(source)
    is_folder = os.path.isdir(source)
    if out_abs == src_abs:
        raise InvalidInput("The output file can't be the source file itself")
    if is_folder and out_abs.startswith(src_abs + os.sep):
        raise InvalidInput("The output file can't be inside the folder being encrypted")

    skipped_links: list[str] = []
    fd, tmp = tempfile.mkstemp(prefix=f".{os.path.basename(out_abs)}.qc-enc-",
                               dir=os.path.dirname(out_abs) or None)
    os.close(fd)
    try:
        if is_folder:
            orig = os.path.basename(src_abs.rstrip(os.sep)) + ".zip"

            def src_path(sink):
                """Archive the folder into the cipher's sink."""
                skipped_links.extend(zip_folder(
                    source, sink, progress_cb=progress,
                    cancel_check=cancel_check, skip_path=tmp))
        else:
            src_path = source
            orig = os.path.basename(source)

        with open(tmp, "wb") as f:
            if embed_binary:
                with open(embed_binary, "rb") as df:
                    while True:
                        chunk = df.read(1 << 20)
                        if not chunk:
                            break
                        f.write(chunk)
            payload_offset = f.tell()
            if single:
                meta = cc.encrypt_single_streaming(
                    src_path, f, password, filename=orig,
                    progress_cb=progress, cancel_check=cancel_check)
                shares: list[str] = []
            else:
                meta, shares = cc.encrypt_shamir_streaming(
                    src_path, f, n, k, filename=orig,
                    progress_cb=progress, cancel_check=cancel_check)
            # Format 2 records (and authenticates) the offset itself; a
            # format-1 writer would not have.
            meta.setdefault("payload_offset", payload_offset)
            if progress:
                progress("Writing binary... 100%")
            blob = json.dumps({"meta": meta}, separators=(",", ":")).encode()
            f.write(cc.MAGIC + len(blob).to_bytes(4, "big") + blob)
            # The plaintext may be deleted the moment this returns, so
            # ciphertext whose blocks never reached disk is unrecoverable.
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, out_abs)
        _fsync_dir(out_abs)
        if embed_binary:
            try:
                os.chmod(out_abs, os.stat(out_abs).st_mode | 0o110)
            except OSError:
                pass
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return {
        "output": out_abs,
        "size": os.path.getsize(out_abs),
        "filename": orig,
        "mode": "single" if single else "shamir",
        "threshold": None if single else k,
        "total": None if single else n,
        "shares": [] if single else shares_with_mnemonics(shares, k),
        # Reported, not silently dropped: the caller is the only one who can
        # tell the user which links did not make it into the container.
        "skipped_symlinks": skipped_links,
    }


def decrypt_qcx(path: str, output_dir: str, *, password: str | None = None,
                shares: Iterable[str] | None = None, verify_only: bool = False,
                progress: Progress = None, cancel_check: CancelCheck = None) -> dict:
    """Decrypt ``path`` into ``output_dir`` under its original filename, or
    just prove the credentials when ``verify_only``.  Never overwrites."""
    meta = load_pkg(path)["meta"]
    final_key, _hmac_key = derive_final_key(
        meta, password=password, shares=shares,
        progress=progress, cancel_check=cancel_check)
    if verify_only:
        if progress:
            progress("Checking file integrity...")
        verify_first_chunk(path, meta, final_key)
        return {"verified": True, "mode": meta["mode"]}

    if not os.path.isdir(output_dir):
        raise InvalidInput(f"The output folder doesn't exist: {output_dir}")
    fd, tmp = tempfile.mkstemp(prefix=".qc-decrypt-", dir=output_dir)
    try:
        with os.fdopen(fd, "wb") as f:
            try:
                fname, orig_size, ts = cc.decrypt_streaming(
                    path, f, meta, final_key,
                    progress_cb=progress, cancel_check=cancel_check)
            except CancelledOperation:
                raise
            except Exception as exc:
                low = (str(exc) or type(exc).__name__).lower()
                if "invalidtag" in low or "authentication" in low:
                    # derive_final_key already proved the key (envelope +
                    # HMAC), so a chunk that fails to authenticate is damage.
                    raise CorruptPayload(
                        "The file's contents are damaged or were altered after "
                        "encryption. The password is right, but this copy can't "
                        "be restored. Try another copy or a backup.") from exc
                raise
            # Symmetric with the encrypt path: a power cut costs a re-decrypt
            # rather than data, but the result is placed as complete.
            f.flush()
            os.fsync(f.fileno())
        name = safe_output_name(fname)
        out, renamed = _place_without_clobber(tmp, output_dir, name)
        _mark_quarantined(out)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    if ts:
        try:
            os.utime(out, (ts, ts))
        except (OSError, OverflowError, ValueError, TypeError):
            pass
    return {
        "output": out,
        "filename": name,
        "size": os.path.getsize(out),
        "original_size": orig_size,
        "timestamp": ts,
        "renamed": renamed,
    }
