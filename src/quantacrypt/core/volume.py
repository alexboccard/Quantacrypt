"""QuantaCrypt Encrypted Volume (.qcv) — file-level encrypted container.

A .qcv file stores an encrypted virtual filesystem that can be mounted
as a macOS volume via FUSE.  Files inside the volume are individually
encrypted with chunked AES-256-GCM using the same key derivation as .qcx
(Argon2id + Kyber-768 → 512-bit final key).

Container layout:
  [Header 512B] [Auth Params (cleartext JSON)] [Encrypted Metadata]
  [Encrypted Directory Index] [File Data ...]

Auth Params are stored unencrypted so that the key can be derived from
a password or Shamir shares without already having the key.  They contain
only public-key-like fields (Argon2 salt, KEM ciphertext, encrypted SK)
that do not reveal the plaintext key.

File data uses the same chunked wire format as .qcx:
  [seq:4B][ct_len:4B][ciphertext+16B_tag] per chunk

The directory index maps virtual paths to their encrypted data offsets,
nonces, sizes, and content hashes.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import logging
import os
import secrets
import stat
import struct
import tempfile
import threading
import time
import uuid
from typing import IO, Any, Callable

from quantacrypt.core.crypto import (
    CancelledOperation,
    KEY_BYTES,
    KEM_DEFAULT,
    reject_weak_secret,
    CHUNK_SIZE,
    SHAMIR_PRIME,
    argon2id_derive,
    argon2_params,
    validate_argon2_params,
    validate_kem,
    kyber_keygen,
    kyber_encaps,
    kyber_decaps,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    expand_kem_ss,
    xor_bytes,
    derive_aes_key,
    shamir_split,
    shamir_recover,
    encode_share,
    decode_share,
    _hmac_fields,
    _meta_hmac,
    _verify_meta_hmac,
    _chunk_nonce,
    _chunk_aad,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#: Bound at import: __del__ may run after the os module was torn down.
_os_close = os.close

from quantacrypt.core.errors import CorruptPayload

logger = logging.getLogger(__name__)

# ── Volume constants ────────────────────────────────────────────────────────

VOLUME_MAGIC = b"QCVOL\x01"
# 1: baseline only.  2: append-only journal after the baseline (the layout
# every later version keeps).  3: the auth-params block names its KEM
# (``kem``: ML-KEM-768 for new volumes) and, in password mode, records its
# Argon2id parameters (``argon2``); a block without them is the Kyber-768 /
# shipped-parameters container that versions 1 and 2 wrote.  compact() keeps
# a container's version (a 2 stays a 2) so older builds can still open it.
VOLUME_FORMAT_VERSION = 3
#: The first version with the journal layout; anything below it is rewritten
#: as a baseline on its first save.
_JOURNAL_FORMAT_VERSION = 2
HEADER_SIZE = 512

# Volume uses smaller chunks than .qcx for better random-access performance.
# 64 KB balances GCM overhead (~0.025%) against seek granularity.
VOLUME_CHUNK_SIZE = 64 * 1024  # 64 KB

# Journal compaction.  Replay cost is per record (bodies are seeked over),
# and disk cost is the dead bytes that deletes and overwrites leave behind
# — journal *size* was a proxy for neither, so a volume that was filled and
# emptied kept its full size forever while a large journal of live writes
# was rewritten for nothing.  save() compacts when dead bytes exceed this
# ratio of the live bytes AND the floor, or when the record count exceeds
# _JOURNAL_COMPACT_RECORDS.  See docs/design/volumes-delta-save.md.
_JOURNAL_COMPACT_RATIO = 0.3
_JOURNAL_COMPACT_FLOOR = 8 << 20  # 8 MB of dead space before a rewrite is worth it
_JOURNAL_COMPACT_RECORDS = 10_000  # ~1 s of replay at open()

# Guard rails for journal record sizes — prevent a malicious or truncated
# file from directing us to allocate gigabytes before we detect corruption.
# (These are "obviously too big" bounds, not tight limits.)
_JOURNAL_MAX_HEADER_CT = 1 << 20  # 1 MB of encrypted header JSON is absurd
_JOURNAL_MIN_HEADER_CT = 16       # at minimum, GCM tag

# Same idea for the two length-prefixed blocks read before anything is
# authenticated: the auth-params JSON is a few hundred bytes, and a
# million-entry directory index is ~250 MB.
_MAX_AUTH_PARAMS = 1 << 20   # 1 MiB
_MAX_BLOCK = 1 << 30         # 1 GiB

def _validate_vpath(vpath: str) -> None:
    """Reject non-absolute or traversal-containing virtual paths.

    Mirrors the defensive check in :meth:`VolumeContainer.open` so that
    direct callers (tests, scripts, future batch APIs) can't insert a
    path into ``dir_index`` that would make the volume un-openable on
    the next ``open()``.  Called from every mutating method and from the
    journal replay.
    """
    if not isinstance(vpath, str) or not vpath.startswith("/"):
        raise ValueError(f"vpath must be an absolute path starting with '/': {vpath!r}")
    parts = [p for p in vpath.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ValueError(f"vpath contains path traversal ('..'): {vpath!r}")


# Offsets within the 512-byte header
_OFF_MAGIC     = 0    # 6 bytes
_OFF_VERSION   = 6    # 4 bytes (uint32 BE)
_OFF_VOL_ID    = 10   # 16 bytes (UUID)
_OFF_META_NONCE = 26  # 12 bytes
_OFF_DIR_NONCE  = 38  # 12 bytes
_OFF_RESERVED   = 50  # 462 bytes padding


def _typed_mode(entry: dict, mode: int) -> int:
    """Re-attach *entry*'s own file-type bits to a caller-supplied mode.

    The type never comes from the caller.  A FUSE backend that masks chmod's
    argument with ALLPERMS hands us permission bits only, and an entry stored
    that way reports no file type at all (`ls` shows `?---------`); a caller
    passing S_IFDIR for a file makes the index disagree with itself.  Both
    now reach the journal and survive every reopen, so neither is a mistake
    the next unmount quietly undoes.
    """
    kind = stat.S_IFDIR if entry.get("type") == "dir" else stat.S_IFREG
    return kind | (mode & 0o7777)


# ── Header I/O ──────────────────────────────────────────────────────────────

def write_header(
    f: IO[bytes],
    volume_id: bytes,
    meta_nonce: bytes,
    dir_nonce: bytes,
    version: int = VOLUME_FORMAT_VERSION,
) -> None:
    """Write a 512-byte .qcv header at the current file position."""
    header = bytearray(HEADER_SIZE)
    header[_OFF_MAGIC:_OFF_MAGIC + 6] = VOLUME_MAGIC
    struct.pack_into(">I", header, _OFF_VERSION, version)
    header[_OFF_VOL_ID:_OFF_VOL_ID + 16] = volume_id
    header[_OFF_META_NONCE:_OFF_META_NONCE + 12] = meta_nonce
    header[_OFF_DIR_NONCE:_OFF_DIR_NONCE + 12] = dir_nonce
    f.write(bytes(header))


def _fsync_dir(path: str) -> None:
    """fsync the directory holding ``path`` so a rename is itself durable.

    os.replace() is atomic with respect to ordering, not durability: after a
    power loss the directory entry can point at a file whose data blocks were
    never written. Best-effort — not every filesystem supports it, and a
    failure here must not fail an otherwise complete write.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def read_header(f: IO[bytes]) -> dict:
    """Read and validate a 512-byte .qcv header. Returns parsed fields."""
    raw = f.read(HEADER_SIZE)
    if len(raw) < HEADER_SIZE:
        raise ValueError("File too small to be a valid .qcv volume")

    magic = raw[_OFF_MAGIC:_OFF_MAGIC + 6]
    if magic != VOLUME_MAGIC:
        raise ValueError(
            f"Not a QuantaCrypt volume (bad magic: {magic!r})"
        )

    version = struct.unpack_from(">I", raw, _OFF_VERSION)[0]
    if version < 1 or version > VOLUME_FORMAT_VERSION:
        raise ValueError(
            f"Unsupported volume format version {version} "
            f"(this app supports up to {VOLUME_FORMAT_VERSION})"
        )

    return {
        "version": version,
        "volume_id": raw[_OFF_VOL_ID:_OFF_VOL_ID + 16],
        "meta_nonce": raw[_OFF_META_NONCE:_OFF_META_NONCE + 12],
        "dir_nonce": raw[_OFF_DIR_NONCE:_OFF_DIR_NONCE + 12],
    }


# ── Auth params (unencrypted) ──────────────────────────────────────────────
# Stored as [len:4B][JSON] immediately after the header.  This block holds
# the parameters needed to derive the final key from a password or shares.

def _write_auth_params(f: IO[bytes], auth_params: dict) -> int:
    """Write cleartext auth params block.  Returns bytes written."""
    payload = json.dumps(auth_params, sort_keys=True, separators=(",", ":")).encode()
    f.write(struct.pack(">I", len(payload)))
    f.write(payload)
    return 4 + len(payload)


def _read_auth_params(f: IO[bytes]) -> dict:
    """Read cleartext auth params block from current position."""
    raw_len = f.read(4)
    if len(raw_len) < 4:
        raise ValueError("Unexpected end of volume file reading auth params length")
    payload_len = struct.unpack(">I", raw_len)[0]
    if payload_len > _MAX_AUTH_PARAMS:
        raise ValueError("Volume auth params block is implausibly large; the file may be corrupt")
    payload = f.read(payload_len)
    if len(payload) < payload_len:
        raise ValueError("Unexpected end of volume file reading auth params data")
    try:
        auth = json.loads(payload)
    except (ValueError, RecursionError) as exc:
        raise ValueError("Volume auth params are not valid JSON; the file may be corrupt") from exc
    if not isinstance(auth, dict):
        raise ValueError("Volume auth params are not an object; the file may be corrupt")
    # Validated here, before any key derivation reads them.
    validate_kem(auth.get("kem"))
    if "argon2" in auth:
        validate_argon2_params(auth["argon2"])
    # The mode and share counts decide which prompt the UIs show and how
    # many shares op_volume_mount waits for; an unknown mode or a string
    # threshold turned a split-key volume into a password prompt and a
    # TypeError deep in the service instead of "this file is corrupt".
    # Every writer since the first volume commit has put "mode" in the
    # block, so a missing one is corruption or an edit — and defaulting it
    # to "single" is what turned a split-key volume into a password prompt.
    # Say so before any credential is asked for.
    if "mode" not in auth:
        raise ValueError("Volume auth params do not name a mode; "
                         "the file may be corrupt or tampered with")
    mode = auth["mode"]
    if mode not in ("single", "shamir"):
        raise ValueError(f"Volume auth params name an unknown mode {mode!r}; "
                         "the file may be corrupt or tampered with")
    if mode == "shamir":
        for key in ("threshold", "total"):
            v = auth.get(key)
            if not isinstance(v, int) or isinstance(v, bool):
                raise ValueError(f"Volume auth params field {key!r} is not a number; "
                                 "the file may be corrupt or tampered with")
        # Same floor as shamir_split and the .qcx reader: one share alone is
        # not a threshold, and recovering from one computes garbage.
        if not (2 <= auth["threshold"] <= auth["total"] <= 255):
            raise ValueError("Volume auth params carry invalid share counts; "
                             "the file may be corrupt or tampered with")
    return auth


#: Every field the cleartext block may carry.  Each also lives in the sealed
#: metadata; open() requires a sealed one to be present in the block too.
_AUTH_VOCABULARY = ("mode", "threshold", "total", "kem", "argon2", "argon_salt",
                    "kyber_kem_ct", "kyber_sk_enc_nonce", "kyber_sk_enc")


def read_volume_auth_params(path: str) -> tuple[dict, dict]:
    """Read header and auth params from a .qcv file without needing the key.

    Returns (header_dict, auth_params_dict).
    This is the entry point for mounting: read auth params → derive key → open.
    """
    with open(path, "rb") as f:
        header = read_header(f)
        auth_params = _read_auth_params(f)
    return header, auth_params


# ── Metadata block ──────────────────────────────────────────────────────────

def _write_encrypted_block(f: IO[bytes], ciphertext: bytes) -> int:
    """Write [ct_len:4B][ciphertext] and return bytes written."""
    f.write(struct.pack(">I", len(ciphertext)))
    f.write(ciphertext)
    return 4 + len(ciphertext)


def _read_encrypted_block(f: IO[bytes]) -> bytes:
    """Read [ct_len:4B][ciphertext] from current position."""
    raw_len = f.read(4)
    if len(raw_len) < 4:
        raise ValueError("Unexpected end of volume file reading block length")
    ct_len = struct.unpack(">I", raw_len)[0]
    if ct_len > _MAX_BLOCK:
        raise ValueError("Volume block is implausibly large; the file may be corrupt")
    ct = f.read(ct_len)
    if len(ct) < ct_len:
        raise ValueError("Unexpected end of volume file reading block data")
    return ct


def encrypt_metadata(final_key: bytes, metadata: dict) -> tuple[bytes, bytes]:
    """Encrypt volume metadata dict. Returns (nonce, ciphertext_with_tag)."""
    plaintext = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    return aes_gcm_encrypt(final_key, plaintext)


def decrypt_metadata(final_key: bytes, nonce: bytes, ciphertext: bytes) -> dict:
    """Decrypt volume metadata. Returns dict."""
    plaintext = aes_gcm_decrypt(final_key, nonce, ciphertext)
    return json.loads(plaintext)


# ── Directory index ─────────────────────────────────────────────────────────

def encrypt_directory(final_key: bytes, dir_index: dict) -> tuple[bytes, bytes]:
    """Encrypt the directory index. Returns (nonce, ciphertext_with_tag)."""
    plaintext = json.dumps(dir_index, sort_keys=True, separators=(",", ":")).encode()
    return aes_gcm_encrypt(final_key, plaintext)


def decrypt_directory(final_key: bytes, nonce: bytes, ciphertext: bytes) -> dict:
    """Decrypt the directory index. Returns dict."""
    plaintext = aes_gcm_decrypt(final_key, nonce, ciphertext)
    return json.loads(plaintext)


# ── Journal record format (v2) ──────────────────────────────────────────────
# Each record is self-contained so a truncated journal tail is recoverable
# (replay simply stops at the last valid record).  Wire layout:
#   [header_nonce 12B][header_ct_len uint32 BE][header_ct + GCM tag][body]
# The header is an encrypted JSON object describing the op; body bytes are
# the raw encrypted file blob for "write" ops (same chunked AES-GCM format
# used in the baseline data section) or empty otherwise.

def _write_journal_record(
    f: IO[bytes],
    final_key: bytes,
    op: dict,
    body: bytes,
) -> int:
    """Append one journal record at current position. Returns body offset
    (absolute file offset where the body bytes start).  The caller should
    use this to update dir_index entries for "write" ops.

    The AAD binds each record to its byte offset in the container, so an
    attacker with file-access cannot reorder records (e.g. truncate newer
    records and re-shuffle older ones into their slots).  Each record's
    ciphertext is only valid at the position where it was written.
    """
    header_dict = {k: v for k, v in op.items() if k not in ("blob",)}
    header_dict["body_length"] = len(body)
    header_plain = json.dumps(
        header_dict, sort_keys=True, separators=(",", ":")
    ).encode()
    header_nonce = secrets.token_bytes(12)
    start = f.tell()
    aad = start.to_bytes(8, "big")
    header_ct = AESGCM(derive_aes_key(final_key)).encrypt(
        header_nonce, header_plain, aad
    )
    f.write(header_nonce)
    f.write(struct.pack(">I", len(header_ct)))
    f.write(header_ct)
    body_offset = start + 12 + 4 + len(header_ct)
    if body:
        f.write(body)
    return body_offset


def _read_journal_records(
    path: str,
    final_key: bytes,
    start_offset: int,
    end_offset: int,
) -> tuple[list[tuple[dict, int, int]], int, bool]:
    """Read all journal records between *start_offset* and *end_offset*.

    Returns ``(records, valid_end, suspicious)``:
      * *records* — list of (header_dict, body_offset, body_length) tuples.
      * *valid_end* — absolute offset just past the last valid record: the
        effective end of the journal.  Appends must resume (and truncate)
        here, never at raw EOF, or records written after a crash-garbage
        tail become permanently unreachable to replay.
      * *suspicious* — True when replay stopped at bytes that do NOT look
        like a crash-truncated tail.  A crash during save can only leave a
        record that runs out of bytes at EOF (records are written
        sequentially, then fsync'd); a fully-present record that fails
        authentication means corruption or deliberate rollback/tampering.
    """
    aes = AESGCM(derive_aes_key(final_key))
    records: list[tuple[dict, int, int]] = []
    suspicious = False
    with open(path, "rb") as f:
        f.seek(start_offset)
        pos = start_offset
        while pos < end_offset:
            nonce = f.read(12)
            if len(nonce) < 12:
                break
            raw_len = f.read(4)
            if len(raw_len) < 4:
                break
            ct_len = struct.unpack(">I", raw_len)[0]
            if ct_len < _JOURNAL_MIN_HEADER_CT or ct_len > _JOURNAL_MAX_HEADER_CT:
                # These 4 bytes were fully present but are not a plausible
                # record length — garbage where a header should be.
                suspicious = True
                break
            ct = f.read(ct_len)
            if len(ct) < ct_len:
                break
            aad = pos.to_bytes(8, "big")
            try:
                header_plain = aes.decrypt(nonce, ct, aad)
                header = json.loads(header_plain)
            except Exception:
                # A complete record failing authentication is not the crash
                # shape (that runs out of bytes at EOF) — flag it.
                suspicious = True
                break
            if not isinstance(header, dict):
                suspicious = True
                break
            body_length = int(header.get("body_length", 0))
            if body_length < 0:
                suspicious = True
                break
            body_offset = pos + 12 + 4 + ct_len
            # Skip the body without reading it — blobs are loaded lazily
            # via VolumeContainer._get_blob() at their absolute offsets.
            next_pos = body_offset + body_length
            if next_pos > end_offset:
                # Body truncated at EOF — the benign crash shape.
                break
            f.seek(next_pos)
            records.append((header, body_offset, body_length))
            pos = next_pos
    return records, pos, suspicious


# ── Per-file chunk encryption (for volume data section) ─────────────────────

def encrypt_file_data(
    data: bytes,
    final_key: bytes,
    chunk_size: int = VOLUME_CHUNK_SIZE,
) -> tuple[bytes, bytes, int, str]:
    """Encrypt file data into chunked AES-GCM format (in memory).

    Returns (base_nonce, encrypted_blob, chunk_count, sha256_hex).
    The blob uses the same wire format as .qcx streaming:
      [seq:4B][ct_len:4B][ct+tag] per chunk.
    """
    base_nonce = secrets.token_bytes(12)
    aes_key = derive_aes_key(final_key)
    cipher = AESGCM(aes_key)
    content_hash = hashlib.sha256(data)
    chunks = []
    chunk_count = 0
    offset = 0

    while offset < len(data) or chunk_count == 0:
        chunk_data = data[offset:offset + chunk_size]
        is_last = (offset + chunk_size >= len(data))
        nonce = _chunk_nonce(base_nonce, chunk_count)
        aad = _chunk_aad(chunk_count, is_last)
        ct = cipher.encrypt(nonce, chunk_data, aad)
        chunks.append(
            struct.pack(">I", chunk_count)
            + struct.pack(">I", len(ct))
            + ct
        )
        chunk_count += 1
        offset += chunk_size
        if is_last:
            break

    blob = b"".join(chunks)
    return base_nonce, blob, chunk_count, content_hash.hexdigest()


def decrypt_file_data(
    blob: bytes,
    final_key: bytes,
    base_nonce: bytes,
    chunk_count: int,
) -> bytes:
    """Decrypt chunked AES-GCM file data from a blob.

    Returns the plaintext bytes.
    """
    aes_key = derive_aes_key(final_key)
    cipher = AESGCM(aes_key)
    plaintext_parts = []
    pos = 0

    for i in range(chunk_count):
        is_last = (i == chunk_count - 1)
        if pos + 8 > len(blob):
            raise ValueError("File data truncated: missing chunk header")
        seq = struct.unpack_from(">I", blob, pos)[0]
        if seq != i:
            raise ValueError(f"Chunk sequence mismatch at {i} (got {seq})")
        ct_len = struct.unpack_from(">I", blob, pos + 4)[0]
        pos += 8
        if pos + ct_len > len(blob):
            raise ValueError("File data truncated: incomplete chunk")
        ct = blob[pos:pos + ct_len]
        pos += ct_len

        nonce = _chunk_nonce(base_nonce, i)
        aad = _chunk_aad(i, is_last)
        try:
            plain = cipher.decrypt(nonce, ct, aad)
        except Exception:
            raise ValueError(
                f"Authentication failed on chunk {i}: "
                "the data may be corrupt or the wrong key was used"
            )
        plaintext_parts.append(plain)

    return b"".join(plaintext_parts)


# ── Key derivation for volumes ──────────────────────────────────────────────
# Reuses the exact same scheme as .qcx files.

def _auth_bytes(meta: dict, key: str) -> bytes:
    v = meta[key]
    if not isinstance(v, str):
        raise ValueError(f"Volume auth field {key!r} is not text; the file may be corrupt")
    try:
        return base64.b64decode(v, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Volume auth field {key!r} is not valid; the file may be corrupt") from exc


def derive_volume_key_single(password: str, meta: dict) -> bytes:
    """Derive the final key for a password-protected volume.

    Expects meta to contain: argon_salt, kyber_kem_ct, kyber_sk_enc_nonce,
    kyber_sk_enc (all base64-encoded), plus — from format 3 — ``kem`` and
    ``argon2``; absent, the legacy KEM and the shipped parameters apply.
    """
    def d64(k): return _auth_bytes(meta, k)

    kem = validate_kem(meta.get("kem"))
    argon_key = argon2id_derive(password.encode(), d64("argon_salt"), meta.get("argon2"))
    sk = aes_gcm_decrypt(argon_key, d64("kyber_sk_enc_nonce"), d64("kyber_sk_enc"))
    kem_ss = _decaps_proven(sk, d64("kyber_kem_ct"), kem)
    return xor_bytes(argon_key, kem_ss)


def derive_volume_key_shamir(share_strings: list[str], meta: dict) -> bytes:
    """Derive the final key for a Shamir-protected volume.

    Expects meta to contain: kyber_kem_ct, kyber_sk_enc_nonce, kyber_sk_enc
    (all base64-encoded), plus ``kem`` from format 3.
    """
    def d64(k): return _auth_bytes(meta, k)

    kem = validate_kem(meta.get("kem"))
    share_dicts = [decode_share(s) for s in share_strings]
    master_key = shamir_recover(share_dicts)
    sk = aes_gcm_decrypt(master_key, d64("kyber_sk_enc_nonce"), d64("kyber_sk_enc"))
    kem_ss = _decaps_proven(sk, d64("kyber_kem_ct"), kem)
    return xor_bytes(master_key, kem_ss)


def _decaps_proven(sk: bytes, kem_ct: bytes, kem: str) -> bytes:
    """Decapsulate after the KEM private key has unsealed.

    Unsealing ``kyber_sk_enc`` is the credential proof: a wrong password or
    share set fails there.  A failure past it — a ciphertext of the wrong
    length, the other KEM's name — is tampering or damage, and must not be
    reported as a wrong password.
    """
    try:
        return kyber_decaps(sk, kem_ct, kem)
    except Exception as exc:
        raise CorruptPayload(
            "The password or shares are right, but this volume's key data was "
            "tampered with or damaged after it was created. It cannot be "
            "opened; restore it from a backup.") from exc


# ── Volume creation ─────────────────────────────────────────────────────────

def _write_new_container(
    path: str,
    volume_id: bytes,
    meta_nonce: bytes,
    dir_nonce: bytes,
    auth_params: dict,
    meta_ct: bytes,
    dir_ct: bytes,
) -> None:
    """Write a fresh container beside *path*, then replace it atomically.

    The scratch file gets a random name rather than ``path + ".part"``: a
    fixed name that outlives a failure wedges that path permanently, because
    every retry then collides with it and no screen in the app knows the name
    to offer clearing it.  Any failure — ENOSPC being the realistic one —
    removes the scratch file, matching encrypt_to_qcx() and compact().

    mkstemp also creates the file 0600, so the container starts out readable
    only by its owner, as .qcx output already does.
    """
    fd, tmp = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.qc-vol-",
        dir=os.path.dirname(os.path.abspath(path)) or None,
    )
    os.close(fd)
    try:
        with open(tmp, "wb") as f:
            write_header(f, volume_id, meta_nonce, dir_nonce)
            _write_auth_params(f, auth_params)
            _write_encrypted_block(f, meta_ct)
            _write_encrypted_block(f, dir_ct)
            # Durability before atomicity: for a Shamir volume the shares are
            # handed out the moment this returns, so a container whose blocks
            # never reached disk is unrecoverable by design.
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(path)


def create_volume_single(
    path: str,
    password: str,
    progress_cb: Callable[[str], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> dict:
    """Create an empty .qcv volume protected by a password.

    Enforces the same minimum length as .qcx encryption — a volume is the
    longer-lived container of the two.

    Returns the volume metadata dict.
    """
    def _p(m):
        if cancel_check and cancel_check():
            raise CancelledOperation("Volume creation cancelled")
        if progress_cb:
            progress_cb(m)

    reject_weak_secret(password)

    _p("Deriving 512-bit password key (Argon2id)...")
    argon_salt = secrets.token_bytes(32)
    argon2 = argon2_params()
    argon_key = argon2id_derive(password.encode(), argon_salt, argon2)

    _p("Generating ML-KEM-768 keypair...")
    pk, sk = kyber_keygen(KEM_DEFAULT)

    _p("Encapsulating + HKDF-SHA-512 expanding to 512 bits...")
    kem_ct, kem_ss = kyber_encaps(pk, KEM_DEFAULT)
    final_key = xor_bytes(argon_key, kem_ss)

    _p("Encrypting KEM private key...")
    sk_nonce, sk_ct = aes_gcm_encrypt(argon_key, sk)

    # Build metadata
    def b64(b): return base64.b64encode(b).decode()
    volume_id = uuid.uuid4().bytes

    auth_fields = {
        "kem":                KEM_DEFAULT,
        "argon2":             argon2,
        "argon_salt":         b64(argon_salt),
        "kyber_kem_ct":       b64(kem_ct),
        "kyber_sk_enc_nonce": b64(sk_nonce),
        "kyber_sk_enc":       b64(sk_ct),
    }

    # Auth params stored unencrypted so mounting can derive the key.  open()
    # checks this block against the sealed copy in the metadata, so
    # tampering with it can only produce a wrong key, never a wrong story.
    auth_params = {
        "mode": "single",
        **auth_fields,
    }

    metadata = {
        "format_version": VOLUME_FORMAT_VERSION,
        "mode": "single",
        "key_bits": 512,
        "chunk_size": VOLUME_CHUNK_SIZE,
        "created_at": int(time.time()),
        **auth_fields,
    }
    metadata["hmac"] = _meta_hmac(final_key, _hmac_fields(metadata))

    # Empty directory
    dir_index: dict[str, Any] = {}

    # Encrypt metadata and directory
    meta_nonce, meta_ct = encrypt_metadata(final_key, metadata)
    dir_nonce, dir_ct = encrypt_directory(final_key, dir_index)

    _p("Writing volume container...")
    _write_new_container(path, volume_id, meta_nonce, dir_nonce,
                         auth_params, meta_ct, dir_ct)
    _p("Volume created.")
    return metadata


def create_volume_shamir(
    path: str,
    n: int,
    k: int,
    progress_cb: Callable[[str], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> tuple[dict, list[str]]:
    """Create an empty .qcv volume protected by Shamir secret sharing.

    Returns (metadata_dict, share_strings).
    """
    def _p(m):
        if cancel_check and cancel_check():
            raise CancelledOperation("Volume creation cancelled")
        if progress_cb:
            progress_cb(m)

    _p("Generating 512-bit random master key...")
    master_key = secrets.token_bytes(KEY_BYTES)

    _p("Generating ML-KEM-768 keypair...")
    pk, sk = kyber_keygen(KEM_DEFAULT)

    _p("Encapsulating + HKDF-SHA-512 expanding to 512 bits...")
    kem_ct, kem_ss = kyber_encaps(pk, KEM_DEFAULT)
    final_key = xor_bytes(master_key, kem_ss)

    _p("Encrypting KEM private key under master key...")
    sk_nonce, sk_ct = aes_gcm_encrypt(master_key, sk)

    _p(f"Splitting 512-bit key into {n} shares (threshold {k})...")
    raw_shares = shamir_split(master_key, n, k)
    share_strings = [encode_share(s) for s in raw_shares]

    def b64(b): return base64.b64encode(b).decode()
    volume_id = uuid.uuid4().bytes

    auth_fields = {
        "kem":                KEM_DEFAULT,
        "kyber_kem_ct":       b64(kem_ct),
        "kyber_sk_enc_nonce": b64(sk_nonce),
        "kyber_sk_enc":       b64(sk_ct),
    }

    # Auth params stored unencrypted so mounting can derive the key
    auth_params = {
        "mode": "shamir",
        "threshold": k,
        "total": n,
        **auth_fields,
    }

    metadata = {
        "format_version": VOLUME_FORMAT_VERSION,
        "mode": "shamir",
        "key_bits": 512,
        "threshold": k,
        "total": n,
        "chunk_size": VOLUME_CHUNK_SIZE,
        "created_at": int(time.time()),
        **auth_fields,
    }
    # HMAC under final_key (not master_key) so that VolumeContainer.open()
    # can verify it without having to plumb master_key through the mount API.
    metadata["hmac"] = _meta_hmac(final_key, _hmac_fields(metadata))

    dir_index: dict[str, Any] = {}

    meta_nonce, meta_ct = encrypt_metadata(final_key, metadata)
    dir_nonce, dir_ct = encrypt_directory(final_key, dir_index)

    _p("Writing volume container...")
    _write_new_container(path, volume_id, meta_nonce, dir_nonce,
                         auth_params, meta_ct, dir_ct)
    _p("Volume created.")
    return metadata, share_strings


# ── Volume open / read / write / save ───────────────────────────────────────

class VolumeContainer:
    """In-memory representation of an open .qcv volume.

    After opening, the directory index lives in memory. File data is read
    from / written to the container on demand. Call save() to persist the
    updated directory index back to disk.
    """

    #: Set by mount_volume() when the container or its directory refuses
    #: writes.  The FUSE layer refuses every mutation before touching state,
    #: so nothing here ever tries to save.
    read_only: bool = False

    def __init__(self, path: str, final_key: bytes):
        self.path = path
        self.final_key = final_key
        self.header: dict = {}
        self.auth_params: dict = {}
        self.metadata: dict = {}
        self.dir_index: dict[str, dict] = {}
        # _file_data holds encrypted blobs for files written this session
        # but not yet flushed to disk.  On open() we intentionally do NOT
        # pre-load all blobs — unmodified files are read lazily via
        # _get_blob() so mount RAM stays bounded by the working set.
        self._file_data: dict[str, bytes] = {}
        self._data_offset: int = 0
        self._file_size: int = 0
        # Format-v2 journal bookkeeping.  _journal_start is the absolute
        # byte offset where the append-only journal begins (= end of the
        # baseline blobs section).  _baseline_size is the size of the
        # baseline blobs section alone (used to decide when to compact).
        # _pending_ops records changes since the last save() so save()
        # can emit them as journal records in one append.
        self._baseline_size: int = 0
        self._journal_start: int = 0
        # Absolute offset just past the last VALID journal record.  Appends
        # seek+truncate here (not EOF) so a crash-garbage tail can never
        # orphan subsequent saves — replay stops at the first bad record,
        # so anything written past it would be silently unreachable.
        self._journal_end: int = 0
        # True when open() found a complete journal record that failed
        # authentication — the tamper/corruption shape, as opposed to the
        # benign run-out-of-bytes-at-EOF crash shape.
        self.journal_suspicious: bool = False
        # Where the unreadable journal tail was copied, when one existed.
        self.suspect_sidecar: str | None = None
        # Paths known to exist on disk (baseline or journal) as of the last
        # successful open/save/compact.  Coalescing consults this to decide
        # whether a delete/rename needs a tombstone record: dropping the
        # record is only safe for paths created purely in-session.
        self._persisted_paths: set[str] = set()
        self._pending_ops: list[dict] = []
        self._dirty = False
        # Records currently in the journal — replay cost is per record, so
        # this is one of save()'s two compaction triggers.
        self._journal_records: int = 0
        # A read descriptor held for the container's life.  Blob reads are
        # pread() at absolute offsets, so it needs no position and is safe
        # to share between FUSE workers; opening the file per 64 KB chunk
        # cost more than the read itself (44 µs vs 2.5 µs, measured).
        # compact() replaces the inode, so it drops the descriptor.
        self._reader_fd: int | None = None
        self._reader_lock = threading.Lock()
        # True once this session has appended records into the pinned inode
        # (gates the orphaned-inode rescue); a sidecar path once one was
        # written (makes the rescue idempotent).
        self._appended_since_open = False
        self._stale_sidecar: str | None = None
        # Guards the check-and-claim of _stale_sidecar so two tear-down
        # rescues (one under the FUSE _lock, one on the lock-free signal
        # path) cannot both create a sidecar across a wall-clock second
        # boundary (review run 22 F-002).  Held only around the O_EXCL
        # reservation, never the copy.
        self._stale_lock = threading.Lock()

    def close(self) -> None:
        """Release the read descriptor.  Safe to call more than once."""
        with self._reader_lock:
            fd, self._reader_fd = self._reader_fd, None
        if fd is not None:
            try:
                _os_close(fd)
            except OSError:
                pass

    def __del__(self):
        # Every opened container now holds a descriptor for its whole life
        # (the pinned reader); at interpreter teardown module globals are
        # already None, hence the bound primitive and the broad guard.
        try:
            self.close()
        except (AttributeError, TypeError, OSError):
            pass

    def discard_unsaved(self) -> None:
        """Drop every unsaved change and re-read the index from disk.

        For a mount that lost writability: the change that hit the failure
        is reported to the caller, and nothing in memory may keep serving
        it (a phantom directory, bytes that vanish at the next mount).

        The fresh state is built on the side and adopted only if the re-open
        succeeds: a re-open that raises (the same permission change removed
        read as well as write) must leave memory exactly as it was, not
        half-cleared with a phantom entry whose blob is already gone
        (review run 20 F-101).
        """
        fresh = VolumeContainer(self.path, self.final_key)
        fresh.open(credential_proven=True)          # may raise — memory untouched
        self.dir_index = fresh.dir_index
        self.metadata = fresh.metadata
        self.header = fresh.header
        self._data_offset = fresh._data_offset
        self._file_size = fresh._file_size
        self._baseline_size = fresh._baseline_size
        self._journal_start = fresh._journal_start
        self._journal_end = fresh._journal_end
        self._journal_records = fresh._journal_records
        self.journal_suspicious = fresh.journal_suspicious
        self.suspect_sidecar = fresh.suspect_sidecar
        with self._reader_lock:
            old_fd, self._reader_fd = self._reader_fd, fresh._reader_fd
        with fresh._reader_lock:
            fresh._reader_fd = None
        if old_fd is not None:
            try:
                _os_close(old_fd)
            except OSError:
                pass
        self._pending_ops.clear()
        self._file_data.clear()
        self._dirty = False
        self._appended_since_open = False

    def _pread(self, offset: int, length: int) -> bytes:
        """Read *length* bytes at absolute *offset* of the container."""
        with self._reader_lock:
            if self._reader_fd is None:
                self._reader_fd = os.open(self.path, os.O_RDONLY)
            fd = self._reader_fd
        parts: list[bytes] = []
        remaining = length
        while remaining > 0:
            chunk = os.pread(fd, remaining, offset)
            if not chunk:
                break
            parts.append(chunk)
            offset += len(chunk)
            remaining -= len(chunk)
        return parts[0] if len(parts) == 1 else b"".join(parts)

    def open(self, credential_proven: bool = False) -> None:
        """Read and decrypt the volume header, metadata, and directory.

        File data blobs are NOT read eagerly — they're loaded on demand by
        read_file() so mount latency stays bounded regardless of container
        size.  We only verify that each entry's offset+length falls within
        the container (defense-in-depth; GCM catches the rest on read).

        Raises ``ValueError`` for corrupt or unreadable volumes, and
        wraps decryption failures with a user-friendly message hinting
        at a wrong password/key.
        """
        with open(self.path, "rb") as f:
            self.header = read_header(f)
            self.auth_params = _read_auth_params(f)
            meta_ct = _read_encrypted_block(f)
            dir_ct = _read_encrypted_block(f)
            self._data_offset = f.tell()
            # Record the container size so bounds checks don't require
            # re-stat'ing the file on every _get_blob() call.
            f.seek(0, 2)
            self._file_size = f.tell()

        try:
            self.metadata = decrypt_metadata(
                self.final_key, self.header["meta_nonce"], meta_ct
            )
        except Exception as exc:
            if credential_proven:
                # The key came out of this container's own auth block (the
                # caller derived it and the KEM private key unsealed), so
                # the password/shares are right: only the sealed metadata or
                # the header nonce it was sealed under can be wrong.
                raise CorruptPayload(
                    "The password or shares are right, but this volume's "
                    "metadata was tampered with or damaged after it was "
                    "created. It cannot be opened; restore it from a backup."
                ) from exc
            raise ValueError(
                "Could not decrypt volume metadata. "
                "The password or key may be incorrect, "
                "or the volume file is corrupt"
            ) from exc

        # Verify metadata HMAC to detect tampering with the auth fields
        # (argon_salt, kyber_kem_ct, kyber_sk_enc_nonce, kyber_sk_enc).  Both
        # volume modes now HMAC under final_key, so this works for single and
        # shamir without additional plumbing.
        _verify_meta_hmac(self.final_key, self.metadata)

        # The cleartext auth-params block is what mount and inspect read
        # before any credential exists (mode, threshold, KEM, parameters).
        # Every one of its fields also lives in the GCM-sealed metadata;
        # a mismatch means the cleartext copy was edited — a wrong key
        # would already have failed above, so this can only be tampering.
        for k, v in self.auth_params.items():
            if k in self.metadata and self.metadata[k] != v:
                raise ValueError(
                    f"Volume auth params field {k!r} does not match the sealed "
                    "metadata: the volume file has been tampered with"
                )
        # A key *removed* from the block escapes the loop above, and a
        # removed "mode"/"threshold" turned a split-key volume into a
        # password prompt: every sealed auth field must still be there.
        for k in _AUTH_VOCABULARY:
            if k in self.metadata and k not in self.auth_params:
                raise ValueError(
                    f"Volume auth params field {k!r} was removed from the "
                    "cleartext block: the volume file has been tampered with"
                )
        # The 4-byte header version sits outside both the sealed metadata
        # and the cleartext block.  Rewriting it 3→2 opened fine, and the
        # next compact() wrote a "v2" container whose auth block still named
        # an ML-KEM ciphertext — an older release then reported a wrong
        # password.  (Binding the header as AAD waits for a format bump.)
        sealed_version = self.metadata.get("format_version")
        if sealed_version is not None and sealed_version != self.header["version"]:
            raise ValueError(
                f"Volume header says format {self.header['version']} but the "
                f"sealed metadata says {sealed_version}: the volume file has "
                "been tampered with"
            )

        try:
            self.dir_index = decrypt_directory(
                self.final_key, self.header["dir_nonce"], dir_ct
            )
        except Exception as exc:
            raise ValueError(
                "Could not decrypt volume directory index. "
                "The volume file may be corrupt"
            ) from exc

        # Pin the inode this index describes now, not at the first read: a
        # read-only mount beside a writer whose compact() replaced the file
        # would otherwise open the new inode against the old offsets and
        # fail every read.  A pinned reader serves a consistent snapshot;
        # compact() in this process drops it via close() before rewriting.
        with self._reader_lock:
            if self._reader_fd is None:
                self._reader_fd = os.open(self.path, os.O_RDONLY)
        self._appended_since_open = False

        # Validate directory index keys: reject absolute-escape, traversal,
        # and non-absolute entries that an attacker could inject by tampering
        # with the encrypted directory block on disk.  AES-GCM already catches
        # bit flips, but this is defense-in-depth.
        for vpath in self.dir_index:
            try:
                _validate_vpath(vpath)
            except ValueError as exc:
                raise ValueError(
                    f"{exc} (the volume file may be corrupt or tampered with)"
                ) from exc

        # Bounds-check each baseline file entry against the baseline size.
        # For v1 containers, baseline == entire data section (no journal).
        # For v2, the journal starts immediately after the baseline blobs;
        # any baseline entry that extends past _baseline_size is corrupt.
        self._baseline_size = sum(
            e.get("data_length", 0)
            for e in self.dir_index.values()
            if e.get("type") != "dir"
        )
        self._journal_start = self._data_offset + self._baseline_size
        # The baseline section must fit entirely within the file; anything
        # less means the container has been truncated inside the canonical
        # data and we have no safe recovery.  (A truncated *journal* tail
        # is tolerated — that's just a crash during save — but baseline
        # truncation is always an error.)
        if self._file_size < self._journal_start:
            raise ValueError(
                f"Volume file truncated within baseline data "
                f"(expected at least {self._journal_start} bytes, "
                f"got {self._file_size}). The volume file may be corrupt"
            )
        # A v1 container must have nothing beyond the baseline; a v2
        # container may legitimately have a journal there.
        if self.header.get("version", 1) < 2 and self._file_size > self._journal_start:
            raise ValueError(
                "Trailing bytes after baseline data in v1 volume. "
                "The volume file may be truncated or corrupt"
            )
        remaining_size = self._baseline_size
        for vpath, entry in self.dir_index.items():
            if entry.get("type") == "dir":
                continue
            offset = entry.get("data_offset", 0)
            length = entry.get("data_length", 0)
            if offset + length > remaining_size:
                raise ValueError(
                    f"File data for {vpath} extends past end of volume "
                    f"(offset {offset} + length {length} > {remaining_size}). "
                    "The volume file may be truncated or corrupt"
                )

        # Replay the append-only journal (v2+).  Each record updates the
        # in-memory dir_index on top of the baseline; write records point
        # future _get_blob() reads into the journal region.  A truncated
        # or corrupt tail is treated as an incomplete append (crash during
        # save): we stop replay at the last valid record and the volume
        # remains consistent.
        self._journal_end = self._journal_start
        self._journal_records = 0
        if (self.header.get("version", 1) >= _JOURNAL_FORMAT_VERSION
                and self._file_size > self._journal_start):
            self._replay_journal()

        # Everything materialised so far exists on disk; coalescing needs
        # this snapshot to emit tombstones for later deletes/renames.
        self._persisted_paths = set(self.dir_index)

    def _preserve_suspect_tail(self, valid_end: int) -> None:
        """Save the unreadable journal tail beside the volume.

        Best-effort: a failure here must never stop the volume opening, since
        the alternative is a user locked out of their own data. Records the
        sidecar path in ``suspect_sidecar`` so the UI can name it.
        """
        self.suspect_sidecar = None
        try:
            tail_len = self._file_size - valid_end
            if tail_len <= 0:
                return
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            sidecar = f"{self.path}.suspect-{stamp}"
            fd = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with open(self.path, "rb") as src, os.fdopen(fd, "wb") as dst:
                    fd = -1  # fdopen owns it now
                    src.seek(valid_end)
                    remaining = tail_len
                    while remaining > 0:
                        chunk = src.read(min(remaining, 1024 * 1024))
                        if not chunk:
                            break
                        dst.write(chunk)
                        remaining -= len(chunk)
            finally:
                if fd >= 0:
                    os.close(fd)
            self.suspect_sidecar = sidecar
            logger.warning(
                "Volume %s: preserved %d unreadable trailing bytes to %s "
                "before they are overwritten by the next save",
                self.path, tail_len, sidecar,
            )
        except OSError as e:
            logger.warning(
                "Volume %s: could not preserve the unreadable journal tail "
                "(%s); it will be lost on the next save",
                self.path, e,
            )

    def _replay_journal(self) -> None:
        """Apply journal records to the in-memory dir_index.

        Reads records starting at ``_journal_start`` until ``_file_size``.
        Each record header is encrypted under ``final_key``; a record whose
        header fails to decrypt (truncated, corrupt, or never fully flushed)
        terminates replay, which is treated as an incomplete append — the
        container state up to that point is consistent.  Records the end of
        the valid journal in ``_journal_end`` and flags a non-crash-shaped
        stop (complete record failing auth) via ``journal_suspicious``.
        """
        records, valid_end, suspicious = _read_journal_records(
            self.path, self.final_key,
            self._journal_start, self._file_size,
        )
        self._journal_end = valid_end
        self._journal_records = len(records)
        self.journal_suspicious = suspicious
        if suspicious:
            logger.warning(
                "Volume %s: journal replay stopped at offset %d with %d "
                "unreadable bytes remaining that do not look like a crash-"
                "truncated tail: possible corruption or tampering; state "
                "reverted to the last valid record",
                self.path, valid_end, self._file_size - valid_end,
            )
            # Copy the tail out NOW, before anything can destroy it. Both
            # persistence paths overwrite it: _append_journal() seeks to
            # _journal_end and truncates, and compact() rewrites the whole
            # container. _persist_locked() runs on nearly every filesystem
            # operation, and macOS writes .DS_Store/Spotlight metadata to a
            # fresh mount within seconds — so the one piece of evidence that
            # a container may have been altered has a lifetime measured in
            # seconds unless it is preserved here, at the only moment it is
            # guaranteed to still exist.
            self._preserve_suspect_tail(valid_end)
        for header, body_offset, body_length in records:
            op_type = header.get("type")
            vpath = header.get("vpath")
            # Skip malformed records defensively; don't abort replay.
            try:
                if not isinstance(vpath, str):
                    continue
                _validate_vpath(vpath)
            except ValueError:
                continue
            if op_type == "write":
                self.dir_index[vpath] = {
                    "type": "file",
                    "size": header.get("size", 0),
                    "mode": header.get("mode", 0o100644),
                    "mtime": header.get("mtime", 0),
                    "nonce": header.get("nonce", ""),
                    "chunk_count": header.get("chunk_count", 0),
                    # data_offset is stored relative to _data_offset so the
                    # same _get_blob() logic works for both baseline and
                    # journal entries.
                    "data_offset": body_offset - self._data_offset,
                    "data_length": body_length,
                    "content_hash": header.get("content_hash", ""),
                }
            elif op_type == "delete":
                self.dir_index.pop(vpath, None)
            elif op_type == "rename":
                new_vpath = header.get("new_vpath")
                if not isinstance(new_vpath, str):
                    continue
                try:
                    _validate_vpath(new_vpath)
                except ValueError:
                    continue
                if vpath in self.dir_index:
                    self.dir_index[new_vpath] = self.dir_index.pop(vpath)
            elif op_type == "setattr":
                entry = self.dir_index.get(vpath)
                if entry is None and not vpath.endswith("/"):
                    entry = self.dir_index.get(vpath + "/")
                if entry is not None:
                    if "mode" in header:
                        # Normalise on the way in too, so an index poisoned
                        # by a build that stored a bare permission mask heals
                        # on the next open instead of staying broken.
                        entry["mode"] = _typed_mode(entry, header["mode"])
                    if "mtime" in header:
                        entry["mtime"] = header["mtime"]
            elif op_type == "mkdir":
                # Directories are cheap to recreate on rmdir/mkdir cycles;
                # replay unconditionally sets the entry.
                if not vpath.endswith("/"):
                    vpath = vpath + "/"
                self.dir_index[vpath] = {
                    "type": "dir",
                    "mode": header.get("mode", 0o40755),
                    "mtime": header.get("mtime", 0),
                }
            elif op_type == "rmdir":
                if not vpath.endswith("/"):
                    vpath = vpath + "/"
                self.dir_index.pop(vpath, None)
            # Unknown op types are silently skipped for forward compat.

    def _get_blob(self, vpath: str) -> bytes:
        """Return the encrypted blob for *vpath*.

        Prefers the in-memory write cache (`_file_data`) so freshly-written
        files don't round-trip through disk, falls back to seek+read on the
        container file for unmodified entries.  Returned bytes are NOT
        cached — the FUSE layer maintains its own decrypted LRU, and we
        don't want to grow _file_data unboundedly on pure-read workloads.
        """
        if vpath in self._file_data:
            return self._file_data[vpath]
        entry = self.dir_index[vpath]
        length = entry.get("data_length", 0)
        if length == 0:
            return b""
        offset = entry.get("data_offset", 0)
        blob = self._pread(self._data_offset + offset, length)
        if len(blob) < length:
            raise ValueError(
                f"File data for {vpath} is truncated on disk "
                f"(expected {length} bytes, got {len(blob)})"
            )
        return blob

    def list_dir(self, dir_path: str = "/") -> list[str]:
        """List entries in a virtual directory."""
        if dir_path != "/" and not dir_path.endswith("/"):
            dir_path += "/"
        if dir_path == "/":
            prefix = "/"
        else:
            prefix = dir_path

        entries = set()
        for vpath in self.dir_index:
            if not vpath.startswith(prefix) or vpath == prefix:
                continue
            # Get the next path component after the prefix
            remainder = vpath[len(prefix):]
            if "/" in remainder:
                # It's a subdirectory entry
                entries.add(remainder.split("/")[0])
            else:
                entries.add(remainder)
        return sorted(entries)

    def read_file(self, vpath: str, verify_hash: bool = True) -> bytes:
        """Decrypt and return file contents.

        If *verify_hash* is True (default) and the directory entry stores
        a ``content_hash``, the SHA-256 of the decrypted data is checked
        against it.  A mismatch raises ``ValueError``.
        """
        # All exceptions here carry an errno: fusepy maps OSError to
        # -e.errno, and its error wrapper does ``e.errno > 0`` — an
        # errno-less exception (errno is None) raises TypeError inside
        # fusepy and returns a garbage error value to the kernel.
        if vpath not in self.dir_index:
            raise FileNotFoundError(
                errno.ENOENT, f"No such file in volume: {vpath}")
        entry = self.dir_index[vpath]
        if entry.get("type") == "dir":
            raise IsADirectoryError(errno.EISDIR, f"Is a directory: {vpath}")

        chunk_count = entry.get("chunk_count", 0)
        size = entry.get("size", 0)
        data_length = entry.get("data_length", 0)
        chunk_size = self.metadata.get("chunk_size", VOLUME_CHUNK_SIZE)

        # Defense-in-depth bounds check: reject absurd chunk_count /
        # data_length that a tampered directory entry could inject.  Without
        # this, a malformed entry with chunk_count = 2**32 - 1 would loop
        # forever or OOM before AES-GCM authentication could catch it.
        if not isinstance(chunk_count, int) or chunk_count < 0:
            raise ValueError(f"Invalid chunk_count for {vpath}: {chunk_count!r}")
        # Expected max chunks given the declared plaintext size; allow a small
        # slop factor for the final partial chunk.
        max_expected_chunks = max(1, (size + chunk_size - 1) // chunk_size) if size else 1
        if chunk_count > max_expected_chunks:
            raise ValueError(
                f"chunk_count for {vpath} ({chunk_count}) exceeds what {size} "
                f"bytes at chunk_size {chunk_size} would produce "
                f"(max {max_expected_chunks}). The directory entry may be corrupt"
            )

        if chunk_count == 0:
            return b""

        blob = self._get_blob(vpath)

        # Declared data_length must match the on-disk / in-memory blob;
        # a mismatch indicates truncation or tampering that the hash
        # check may miss.
        if data_length != len(blob):
            raise ValueError(
                f"data_length for {vpath} ({data_length}) does not match "
                f"blob length ({len(blob)}). The directory entry may be corrupt"
            )
        if not blob:
            raise ValueError(f"File data missing for {vpath}")

        plaintext = decrypt_file_data(
            blob, self.final_key,
            base64.b64decode(entry["nonce"]),
            chunk_count,
        )

        if verify_hash and "content_hash" in entry:
            actual_hash = hashlib.sha256(plaintext).hexdigest()
            if actual_hash != entry["content_hash"]:
                raise ValueError(
                    f"Content hash mismatch for {vpath}: "
                    f"expected {entry['content_hash'][:16]}…, "
                    f"got {actual_hash[:16]}… (the file may be corrupt)"
                )

        return plaintext

    def _get_blob_range(
        self, vpath: str, entry: dict, start: int, length: int,
    ) -> bytes:
        """Return *length* blob bytes at blob-relative *start* for *vpath*."""
        if vpath in self._file_data:
            chunk = self._file_data[vpath][start:start + length]
        else:
            chunk = self._pread(
                self._data_offset + entry.get("data_offset", 0) + start, length)
        if len(chunk) < length:
            raise ValueError(
                f"File data for {vpath} is truncated on disk "
                f"(expected {length} bytes at blob offset {start}, "
                f"got {len(chunk)})"
            )
        return chunk

    def read_file_range(self, vpath: str, offset: int, size: int) -> bytes:
        """Decrypt and return up to *size* plaintext bytes at *offset*.

        Random access: decrypts only the chunks covering the range —
        O(range), not O(file size).  Possible because every chunk is an
        independent AEAD unit at a deterministic blob offset (all non-last
        chunks carry exactly ``chunk_size`` plaintext, so chunk *i* starts
        at ``i * (8 + chunk_size + 16)``).  The per-chunk AES-GCM tag and
        AAD (index + last-flag) authenticate everything returned; the
        whole-plaintext ``content_hash`` is NOT checked here — use
        ``read_file(verify_hash=True)`` for an end-to-end scan.

        Reads past EOF return the available bytes (empty at/past EOF),
        matching read(2) semantics.
        """
        if offset < 0 or size < 0:
            raise ValueError(f"Negative offset/size: {offset}/{size}")
        if vpath not in self.dir_index:
            raise FileNotFoundError(
                errno.ENOENT, f"No such file in volume: {vpath}")
        entry = self.dir_index[vpath]
        if entry.get("type") == "dir":
            raise IsADirectoryError(errno.EISDIR, f"Is a directory: {vpath}")

        chunk_count = entry.get("chunk_count", 0)
        fsize = entry.get("size", 0)
        data_length = entry.get("data_length", 0)
        chunk_size = self.metadata.get("chunk_size", VOLUME_CHUNK_SIZE)

        # Same tampered-entry bounds check as read_file().
        if not isinstance(chunk_count, int) or chunk_count < 0:
            raise ValueError(f"Invalid chunk_count for {vpath}: {chunk_count!r}")
        max_expected_chunks = (
            max(1, (fsize + chunk_size - 1) // chunk_size) if fsize else 1
        )
        if chunk_count > max_expected_chunks:
            raise ValueError(
                f"chunk_count for {vpath} ({chunk_count}) exceeds what "
                f"{fsize} bytes at chunk_size {chunk_size} would produce "
                f"(max {max_expected_chunks}). The directory entry may be corrupt"
            )

        if chunk_count == 0 or size == 0 or offset >= fsize:
            return b""

        end = min(offset + size, fsize)
        first = offset // chunk_size
        last = min(chunk_count - 1, (end - 1) // chunk_size)
        stride = 8 + chunk_size + 16  # header + ciphertext + GCM tag

        aes_key = derive_aes_key(self.final_key)
        cipher = AESGCM(aes_key)
        base_nonce = base64.b64decode(entry["nonce"])

        parts: list[bytes] = []
        for i in range(first, last + 1):
            cstart = i * stride
            clen = stride if i < chunk_count - 1 else data_length - cstart
            if clen < 8 + 16 or cstart + clen > data_length:
                raise ValueError(
                    f"File data for {vpath} is truncated: chunk {i} "
                    f"does not fit in data_length {data_length}"
                )
            chunk = self._get_blob_range(vpath, entry, cstart, clen)
            seq = struct.unpack_from(">I", chunk, 0)[0]
            ct_len = struct.unpack_from(">I", chunk, 4)[0]
            if seq != i:
                raise ValueError(
                    f"Chunk sequence mismatch at {i} (got {seq})")
            if ct_len != len(chunk) - 8:
                raise ValueError(
                    f"Chunk {i} length mismatch for {vpath} "
                    f"({ct_len} vs {len(chunk) - 8})"
                )
            nonce = _chunk_nonce(base_nonce, i)
            aad = _chunk_aad(i, i == chunk_count - 1)
            try:
                parts.append(cipher.decrypt(nonce, chunk[8:], aad))
            except Exception:
                raise ValueError(
                    f"Authentication failed on chunk {i}: "
                    "the data may be corrupt or the wrong key was used"
                )
            del chunk

        plain = b"".join(parts)
        rel = offset - first * chunk_size
        return plain[rel:rel + (end - offset)]

    def write_file(self, vpath: str, data: bytes, *,
                   mtime: float | None = None, mode: int | None = None) -> None:
        """Encrypt and store file data in the volume.

        The blob lives in _file_data until the next save(), which will
        append it to the journal region of the container (format v2+).
        ``mtime`` lets the FUSE layer keep a timestamp the caller set
        explicitly (cp -p, rsync, tar) before the close that flushes the
        data; without it the flush stamped every copied file with its copy
        time.  ``mode`` is the permission set for a new entry (the kernel's
        umask-applied mode from create(2); every file used to land 0644,
        which is what makes ssh refuse a key written into the vault) or an
        explicit chmod deferred to this flush.
        """
        _validate_vpath(vpath)
        nonce, blob, chunk_count, sha256_hex = encrypt_file_data(
            data, self.final_key, self.metadata.get("chunk_size", VOLUME_CHUNK_SIZE)
        )
        if mtime is None:
            mtime = int(time.time())
        # Preserve a mode an earlier chmod set: rebuilding the entry from
        # scratch made `chmod +x` then any write silently drop the bit.
        existing = self.dir_index.get(vpath)
        if mode is not None:
            mode = stat.S_IFREG | (mode & 0o7777)
        elif existing:
            mode = existing.get("mode", 0o100644)
        else:
            mode = 0o100644
        nonce_b64 = base64.b64encode(nonce).decode()

        self.dir_index[vpath] = {
            "type": "file",
            "size": len(data),
            "mode": mode,
            "mtime": mtime,
            "nonce": nonce_b64,
            "chunk_count": chunk_count,
            "data_offset": 0,  # reset on save() / compact()
            "data_length": len(blob),
            "content_hash": sha256_hex,
        }
        self._file_data[vpath] = blob
        # Record the op so save() can emit one journal record per change.
        self._pending_ops.append({
            "type": "write",
            "vpath": vpath,
            "size": len(data),
            "mode": mode,
            "mtime": mtime,
            "nonce": nonce_b64,
            "chunk_count": chunk_count,
            "content_hash": sha256_hex,
        })
        self._dirty = True

    def set_attrs(self, vpath: str, *, mode: int | None = None,
                  mtime: float | None = None) -> bool:
        """Record a mode and/or mtime change so it survives unmount.

        Previously chmod/utimens mutated the entry in place and marked
        nothing dirty, so the change was discarded at unmount — except when
        an unrelated write happened to trigger compact(), which carried it.
        Same input, different outcome. Since utimens is what cp -p, rsync -t,
        unzip, tar -x and Finder all issue after writing, every file copied
        into a mounted volume came back stamped with its copy time.

        Returns False if the path is unknown.
        """
        entry = self.dir_index.get(vpath)
        if entry is None and not vpath.endswith("/"):
            vpath = vpath + "/"
            entry = self.dir_index.get(vpath)
        if entry is None:
            return False
        op: dict[str, Any] = {"type": "setattr", "vpath": vpath}
        if mode is not None:
            mode = _typed_mode(entry, mode)
            entry["mode"] = mode
            op["mode"] = mode
        if mtime is not None:
            entry["mtime"] = mtime
            op["mtime"] = mtime
        if len(op) == 2:      # nothing actually changed
            return True
        self._pending_ops.append(op)
        self._dirty = True
        return True

    def mkdir(self, vpath: str, mode: int = 0o755) -> None:
        """Create a virtual directory with the caller's (umask-applied)
        permission bits — `mkdir -m 700` and gpg's homedir check depend on
        them surviving."""
        if not vpath.endswith("/"):
            vpath += "/"
        _validate_vpath(vpath)
        if vpath in self.dir_index:
            return  # already exists
        mtime = int(time.time())
        mode = stat.S_IFDIR | (mode & 0o7777)
        self.dir_index[vpath] = {
            "type": "dir",
            "mode": mode,
            "mtime": mtime,
        }
        self._pending_ops.append({
            "type": "mkdir",
            "vpath": vpath,
            "mode": mode,
            "mtime": mtime,
        })
        self._dirty = True

    def delete(self, vpath: str) -> None:
        """Remove a file or empty directory from the volume."""
        _validate_vpath(vpath)
        if vpath not in self.dir_index:
            raise FileNotFoundError(errno.ENOENT, f"No such entry: {vpath}")
        entry = self.dir_index[vpath]
        is_dir = entry.get("type") == "dir"

        # If it's a directory, make sure it's empty
        if is_dir:
            children = self.list_dir(vpath.rstrip("/"))
            if children:
                raise OSError(errno.ENOTEMPTY, f"Directory not empty: {vpath}")

        del self.dir_index[vpath]
        self._file_data.pop(vpath, None)
        self._pending_ops.append({
            "type": "rmdir" if is_dir else "delete",
            "vpath": vpath,
        })
        self._dirty = True

    def rename(self, old_path: str, new_path: str) -> None:
        """Rename a file or directory.

        POSIX rename(2) semantics for the destination: an existing regular
        file is atomically replaced.  This is the editor atomic-save
        pattern (write tmp, rename tmp → final) and macOS renames its
        AppleDouble ``._`` sidecars over existing ones — refusing with
        EEXIST breaks both.  The replaced destination gets a ``delete``
        pending op so the journal carries a tombstone (see
        _coalesce_pending_ops: without it, replay resurrects a persisted
        destination's old content on the next open).
        """
        _validate_vpath(old_path)
        _validate_vpath(new_path)
        if old_path not in self.dir_index:
            # Directory sources: dir keys carry a trailing slash, but FUSE
            # (and most callers) pass slash-less paths.
            old_dir = old_path if old_path.endswith("/") else old_path + "/"
            src = self.dir_index.get(old_dir)
            if src is not None and src.get("type") == "dir":
                new_dir = new_path if new_path.endswith("/") else new_path + "/"
                self._rename_dir(old_dir, new_dir)
                return
            raise FileNotFoundError(errno.ENOENT, f"No such entry: {old_path}")
        if self.dir_index[old_path].get("type") == "dir":
            # Slash-suffixed dir key passed directly.
            new_dir = new_path if new_path.endswith("/") else new_path + "/"
            self._rename_dir(old_path, new_dir)
            return
        if new_path == old_path:
            # POSIX no-op success.  Without this guard the destination-
            # exists branch below deletes the entry (it IS the source),
            # queues a tombstone, then KeyErrors — permanent loss after
            # the next save.
            return
        if not new_path.endswith("/") and new_path + "/" in self.dir_index:
            # Directory destinations arrive slash-less from FUSE; without
            # this check the slash-less lookup below misses the dir entry
            # and installs a FILE key "/d" alongside the DIR key "/d/" —
            # durable twin keys that make the dir's children unreachable.
            raise IsADirectoryError(
                errno.EISDIR, f"Destination is a directory: {new_path}")
        dest = self.dir_index.get(new_path)
        if dest is not None:
            if dest.get("type") == "dir":
                # Directory destinations keep the conservative refusal —
                # subtree semantics are out of scope here (see F-013).
                raise IsADirectoryError(
                    errno.EISDIR, f"Destination is a directory: {new_path}")
            del self.dir_index[new_path]
            self._file_data.pop(new_path, None)
            self._pending_ops.append({
                "type": "delete",
                "vpath": new_path,
            })

        self.dir_index[new_path] = self.dir_index.pop(old_path)
        if old_path in self._file_data:
            self._file_data[new_path] = self._file_data.pop(old_path)
        self._pending_ops.append({
            "type": "rename",
            "vpath": old_path,
            "new_vpath": new_path,
        })
        self._dirty = True

    def _rename_dir(self, old_dir: str, new_dir: str) -> None:
        """Rename a directory subtree (both args slash-suffixed).

        Re-keys the dir entry AND every index key under ``old_dir`` —
        moving only the dir entry would orphan the whole subtree.  Emits
        one rename pending-op per key: journal replay already handles
        per-key renames, so no record type or format rev is needed.

        Destination must not exist (EEXIST for a dir, ENOTDIR for a
        file); dir-over-dir merge semantics are out of scope.  Renaming
        into the source's own subtree is EINVAL, per rename(2).
        """
        if new_dir == old_dir:
            return  # rename(a, a) is a POSIX no-op success
        if new_dir.startswith(old_dir):
            raise OSError(
                errno.EINVAL,
                f"Cannot rename {old_dir} into its own subtree {new_dir}")
        if new_dir.rstrip("/") in self.dir_index:
            raise NotADirectoryError(
                errno.ENOTDIR, f"Destination is a file: {new_dir.rstrip('/')}")
        if new_dir in self.dir_index:
            raise FileExistsError(
                errno.EEXIST, f"Destination directory exists: {new_dir}")

        moves = sorted(
            k for k in self.dir_index
            if k == old_dir or k.startswith(old_dir)
        )
        for k in moves:
            new_k = new_dir + k[len(old_dir):]
            self.dir_index[new_k] = self.dir_index.pop(k)
            if k in self._file_data:
                self._file_data[new_k] = self._file_data.pop(k)
            self._pending_ops.append({
                "type": "rename",
                "vpath": k,
                "new_vpath": new_k,
            })
        self._dirty = True

    def get_entry(self, vpath: str) -> dict | None:
        """Return directory entry metadata, or None if not found."""
        return self.dir_index.get(vpath)

    @property
    def is_dirty(self) -> bool:
        return self._dirty

    def save(self) -> None:
        """Persist pending changes to disk.

        Format-v2 fast path: append pending ops as journal records at the
        end of the container.  This makes save() proportional to the size
        of the changes, not the size of the container — a 1-byte edit on
        a 1 GB volume is ~4 KB of I/O instead of 1 GB.

        Falls back to a full compact when:
          * the container is still format v1 (upgrade to v2 in one shot), or
          * the journal would exceed _JOURNAL_COMPACT_RATIO of the baseline
            after this append (the next open() would spend too long
            replaying).

        Crash safety: each journal record is self-authenticating
        (AES-GCM on the header + empty-AAD body).  A crash mid-append
        leaves a partial record; open() stops replay at the last complete
        record, which is consistent with the last completed save().
        """
        if not self._pending_ops and not self._dirty:
            return

        # Pre-journal containers always upgrade via compact.  This keeps the
        # on-disk version in sync with the actual layout (no mixed v1-header
        # + v2-journal containers in the wild).
        if self.header.get("version", 1) < _JOURNAL_FORMAT_VERSION:
            self.compact()
            return

        coalesced = self._coalesce_pending_ops()
        dead, live = self._dead_and_live_bytes()
        # Both bounds, so small volumes do not rewrite themselves on every
        # save — which would defeat the delta-save win — and so a volume
        # that was filled and then emptied does reclaim its space.
        if dead > _JOURNAL_COMPACT_FLOOR and dead > live * _JOURNAL_COMPACT_RATIO:
            self.compact()
            return
        if self._journal_records + len(coalesced) > _JOURNAL_COMPACT_RECORDS:
            self.compact()
            return

        self._append_journal(coalesced)

    def _dead_and_live_bytes(self) -> tuple[int, int]:
        """``(dead, live)`` data bytes as of now, pending changes included.

        *live* is every file entry's blob length.  *dead* is what the data
        region holds beyond the live blobs that are actually on disk —
        i.e. blobs of deleted files and the previous versions of files that
        have been rewritten (their current blob is still in ``_file_data``,
        so it is not counted as on-disk live).
        """
        live = 0
        live_on_disk = 0
        for vpath, entry in self.dir_index.items():
            if entry.get("type") == "dir":
                continue
            n = entry.get("data_length", 0)
            live += n
            if vpath not in self._file_data:
                live_on_disk += n
        on_disk = max(0, self._journal_end - self._data_offset)
        return max(0, on_disk - live_on_disk), live

    def _coalesce_pending_ops(self) -> list[dict]:
        """Collapse redundant ops before emitting to the journal.

        Handles the common editor atomic-save pattern correctly:
          * ``write /tmp`` + ``rename /tmp → /final`` → emit as a single
            ``write /final`` (the blob is in ``_file_data['/final']`` after
            the rename re-keyed it).  Emitting the write under ``/tmp``
            would look up an empty blob and get silently dropped, losing
            the data.
          * ``write X`` + ``write X`` → keep only the last.
          * ``write X`` + ``delete X`` → drop both **only if X won't exist
            on replay anyway**.  If X persists on disk (baseline or an
            earlier save) — or an emitted rename earlier in this batch
            moves something to X — a ``delete`` tombstone is kept:
            otherwise replay would resurrect the old X on the next open.
          * ``write X`` + ``rename X → Y`` where X exists on replay →
            re-key the write to Y and emit a ``delete X`` tombstone in the
            rename's place (same resurrection hazard).
          * ``rename X → Y`` where ``X`` is a baseline path (not an
            in-session write) → preserved as a rename record.

        Tombstone decisions consult ``on_disk`` — a simulation of which
        paths exist *at that point of the replay*, not the stale
        last-save snapshot.  Emitted renames move names in the simulation
        and deletes remove them; a rename of a baseline path followed by
        write+delete of its destination therefore still emits the
        destination's tombstone, where the snapshot alone would wrongly
        drop it and replay would resurrect the renamed-in old content.
        In-session writes are intentionally NOT added to the simulation:
        their interaction with later ops on the same path goes through
        ``current_owner``, and a write dropped by a later delete never
        materializes anything on replay.

        Returns the coalesced ops in the order they should be emitted.
        """
        ops = self._pending_ops
        # Simulated on-replay existence, advanced op by op (see docstring).
        on_disk = set(self._persisted_paths)
        # Map from "current effective path" → index of the in-session write
        # op that produced that path.  Renames re-key this map; deletes
        # remove from it.
        current_owner: dict[str, int] = {}
        # Indices of ops we should not emit (superseded writes, cancelled
        # deletes, merged-away renames).
        dropped: set[int] = set()
        # For each write op index, its final effective vpath (may differ
        # from the op's originally-recorded vpath if subsequent renames
        # moved it).
        write_final_path: dict[int, str] = {}
        # Ops replaced by a different record (rename of a persisted source
        # whose write was re-keyed → emitted as a delete tombstone instead).
        converted: dict[int, dict] = {}
        # Position at which each surviving write is emitted: its own index,
        # or the index of the LAST rename that re-keyed it.  Emitting a
        # re-keyed write at its original position would reorder it against
        # ops that sit between the write and the rename and touch the
        # destination path (e.g. rename-replace's tombstone for the old
        # destination) — replay would then delete the fresh content.
        emit_pos: dict[int, int] = {}
        # Indices of setattr ops keyed by their current effective path. A
        # setattr is metadata on a name, so it has to follow that name the
        # way a write does: rsync's sequence is write /.f.tmp → chmod/utimes
        # /.f.tmp → rename to /f.txt, and leaving the setattr pinned to the
        # temp emits it against a path that never materialises on replay.
        setattr_owners: dict[str, list[int]] = {}
        # setattr index → position it must be emitted at (always just after
        # the write it belongs to), and its final effective path. Kept
        # separately rather than rewriting the op in place: this function must
        # be free of side effects on _pending_ops, or a second call sees a
        # half-rewritten list and produces a different answer.
        attr_emit_pos: dict[int, int] = {}
        attr_final_path: dict[int, str] = {}

        for i, op in enumerate(ops):
            t = op["type"]
            if t == "write":
                vp = op["vpath"]
                # Supersede any earlier in-session write for this path
                if vp in current_owner:
                    dropped.add(current_owner[vp])
                current_owner[vp] = i
                write_final_path[i] = vp
                emit_pos[i] = i
                # ...and any earlier setattr on it: the write record carries
                # the mode (copied from the in-memory entry, which the
                # setattr already updated) and its own mtime.  Left in
                # setattr_owners, a later rename pinned the stale setattr
                # *after* the re-keyed write, and replay reverted the mtime
                # and mode the write had set — found by the journal fuzz.
                for sidx in setattr_owners.pop(vp, []):
                    dropped.add(sidx)
            elif t == "setattr":
                setattr_owners.setdefault(op["vpath"], []).append(i)
            elif t == "rename":
                old = op["vpath"]
                new = op.get("new_vpath")
                if old in current_owner and isinstance(new, str):
                    # Re-key an in-session write to the new path.  If the
                    # old path exists on replay at this point, replaying
                    # just the re-keyed write would leave that old entry
                    # alive — emit a tombstone for it in this slot.
                    idx = current_owner.pop(old)
                    current_owner[new] = idx
                    write_final_path[idx] = new
                    emit_pos[idx] = i
                    # Carry any attribute changes on the old name across, and
                    # emit them after the re-keyed write so replay applies
                    # them to a path that exists.
                    moved = setattr_owners.pop(old, [])
                    for sidx in moved:
                        attr_final_path[sidx] = new
                        attr_emit_pos[sidx] = i
                    if moved:
                        setattr_owners.setdefault(new, []).extend(moved)
                    if old in on_disk:
                        converted[i] = {"type": "delete", "vpath": old}
                        on_disk.discard(old)
                    else:
                        dropped.add(i)
                else:
                    # Rename of a baseline path — emitted as-is, which
                    # moves the name in the replay simulation.
                    on_disk.discard(old)
                    if isinstance(new, str):
                        on_disk.add(new)
                        # Deliberately NOT re-keyed to `new`. This rename is
                        # emitted at its own index, after the setattr, and
                        # replay's rename moves the whole entry — so an
                        # attribute change applied to the old name travels
                        # with it. Re-keying without also moving the emit
                        # position (as the in-session branch above does) put
                        # the setattr before the path it names existed, and
                        # the change was lost. Only the ownership moves, so a
                        # later delete of `new` still drops it.
                        setattr_owners.setdefault(new, []).extend(
                            setattr_owners.pop(old, []))
            elif t in ("delete", "rmdir"):
                vp = op["vpath"]
                if vp in current_owner:
                    # The in-session write is cancelled either way; the
                    # delete record itself is only droppable if nothing
                    # emitted before it materializes the path on replay.
                    dropped.add(current_owner.pop(vp))
                    if vp in on_disk:
                        on_disk.discard(vp)
                    else:
                        dropped.add(i)
                else:
                    # Delete of a baseline path — emit it as-is.
                    on_disk.discard(vp)
                for sidx in setattr_owners.pop(vp, []):
                    dropped.add(sidx)
            # mkdir is emitted as-is; mkdir-then-rmdir coalescing would be
            # a further refinement but is rarely worth complicating.

        # position → surviving write index to emit there
        writes_at: dict[int, int] = {
            pos: idx for idx, pos in emit_pos.items() if idx not in dropped
        }
        # position → setattr indices to emit there, after that position's write
        attrs_at: dict[int, list[int]] = {}
        for sidx, pos in attr_emit_pos.items():
            if sidx not in dropped:
                attrs_at.setdefault(pos, []).append(sidx)

        coalesced: list[dict] = []
        for i, op in enumerate(ops):
            if i in converted:
                coalesced.append(converted[i])
            elif i not in dropped and op["type"] != "write" and i not in attr_emit_pos:
                final = attr_final_path.get(i)
                coalesced.append({**op, "vpath": final} if final else op)
            if i in writes_at:
                w = ops[writes_at[i]]
                final = write_final_path[writes_at[i]]
                if final != w["vpath"]:
                    w = {**w, "vpath": final}
                coalesced.append(w)
            for sidx in attrs_at.get(i, []):
                a = ops[sidx]
                final = attr_final_path.get(sidx)
                coalesced.append({**a, "vpath": final} if final else a)
        return self._drop_overwritten_tombstones(coalesced)

    @staticmethod
    def _drop_overwritten_tombstones(ops: list[dict]) -> list[dict]:
        """Remove a ``delete X`` that a later record in the same batch
        overwrites (a ``write X``, or a rename onto X).

        Replay's write sets the entry unconditionally and its rename moves
        the whole entry, so the tombstone is redundant — and on a partial
        append it is harmful: the editor atomic-save pattern emitted
        ``[delete /final][write /final]``, and a disk-full error while
        writing the body left the complete tombstone durable while the
        write was not.  A fresh open then showed ``/final`` missing, with
        nothing suspicious to report (measured).  Without the tombstone the
        same failure leaves the previous content in place.
        """
        materialised: set[str] = set()
        kept: list[dict] = []
        for op in reversed(ops):
            t = op["type"]
            if t == "delete" and op["vpath"] in materialised:
                continue
            if t == "write":
                materialised.add(op["vpath"])
            elif t == "rename" and isinstance(op.get("new_vpath"), str):
                materialised.add(op["new_vpath"])
            kept.append(op)
        kept.reverse()
        return kept

    def _check_still_ours(self) -> None:
        """Refuse to write into a file that is no longer the one open() read.

        Identity is the pinned descriptor, not the path.  A sync client
        restoring a version, a backup copied over the vault, a `cp`/`>` that
        overwrites it in place, or a rename/move all change what the path
        holds while the reader keeps serving the opened bytes; a path-based
        append would then acknowledge writes into a foreign file and lose or
        corrupt both parties' data (review runs 19 F-202, 20 F-001/F-002/
        F-201).  ESTALE names the condition; the FUSE layer flips the mount
        read-only and, when the inode was orphaned, rescues it to a sidecar.

        The checks, in order: a *removed* path with an orphaned inode vs a
        *moved* one (the inode still has a name); a *replaced* inode; a
        *shortened* file (longer is our own failed append, truncated on the
        retry); and — the case inode+size cannot see — an *in-place
        overwrite*, caught by re-reading the header through the pinned fd
        and checking it still names this volume.
        """
        with self._reader_lock:
            fd = self._reader_fd
            if fd is None:
                # No pin (a direct caller that close()d, or a fresh format-1
                # container before its first read).  Pin now so the next
                # write has an identity; we cannot vouch for this one.
                try:
                    self._reader_fd = os.open(self.path, os.O_RDONLY)
                except OSError:
                    pass
                return
            pinned = os.fstat(fd)
            header = os.pread(fd, HEADER_SIZE, 0)
        try:
            st = os.stat(self.path)
        except FileNotFoundError as exc:
            if pinned.st_nlink >= 1:
                # The inode still has a name — the container was renamed or
                # moved while mounted; our records are safe in it, but this
                # path can no longer be written.
                raise OSError(errno.ESTALE,
                              "Volume container moved or renamed beneath the mount") from exc
            raise OSError(errno.ESTALE, "Volume container removed beneath the mount") from exc
        if (pinned.st_dev, pinned.st_ino) != (st.st_dev, st.st_ino):
            raise OSError(errno.ESTALE, "Volume container replaced beneath the mount")
        if st.st_size < self._journal_end:
            raise OSError(errno.ESTALE, "Volume container shortened beneath the mount")
        # Same inode, long enough: an in-place overwrite (cp/O_TRUNC, `> file`)
        # keeps the inode and can end >= _journal_end, so only the header
        # tells us the bytes are no longer ours.  A residual older copy of the
        # *same* volume that is also long enough is the documented format-work
        # gap (length trailer + header-as-AAD).
        vol_id = self.header.get("volume_id")
        if (len(header) < _OFF_VOL_ID + 16
                or header[_OFF_MAGIC:_OFF_MAGIC + 6] != VOLUME_MAGIC
                or (vol_id is not None
                    and header[_OFF_VOL_ID:_OFF_VOL_ID + 16] != vol_id)):
            raise OSError(errno.ESTALE, "Volume container overwritten beneath the mount")

    def rescue_if_orphaned(self) -> "str | None":
        """If the pinned inode has lost its name — a foreign replace, remove
        or overwrite unlinked what this mount opened — and this session
        appended records, copy the inode to a ``<path>.stale-<stamp>``
        sidecar so those records survive the unmount that frees the fd
        (review run 20 F-002).  Idempotent; returns the sidecar path or None.

        Not for the in-place-overwrite or shortened cases: there the inode
        still has a name (or is truncated in place), so its bytes are the
        foreign ones, not ours — nothing to rescue.
        """
        # Claim the sidecar name atomically: check _stale_sidecar, snapshot
        # the fd, and reserve the O_EXCL file under one lock so a concurrent
        # rescue on the same container sees the claim and returns it rather
        # than creating a second file (review run 22 F-002).  The copy runs
        # outside the lock.
        with self._stale_lock:
            if self._stale_sidecar is not None:
                return self._stale_sidecar
            with self._reader_lock:
                fd = self._reader_fd
            if fd is None or not self._appended_since_open:
                return None
            try:
                st = os.fstat(fd)
            except OSError:
                return None
            if st.st_nlink != 0:
                return None
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            sidecar = f"{self.path}.stale-{stamp}"
            try:
                out = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except OSError as exc:
                logger.warning("Volume %s: could not preserve the orphaned "
                               "container (%s)", self.path, exc)
                return None
            self._stale_sidecar = sidecar          # claimed; a concurrent caller now returns it
        try:
            with os.fdopen(out, "wb") as dst:
                off, size = 0, st.st_size
                while off < size:
                    chunk = os.pread(fd, min(1 << 20, size - off), off)
                    if not chunk:
                        break
                    dst.write(chunk)
                    off += len(chunk)
            logger.warning(
                "Volume %s: the container was replaced beneath the mount; the "
                "volume as this mount had it was preserved to %s",
                self.path, sidecar)
            return sidecar
        except OSError as exc:
            logger.warning("Volume %s: could not preserve the orphaned "
                           "container (%s)", self.path, exc)
            return None

    def _append_journal(self, ops: list[dict] | None = None) -> None:
        """Append pending ops as journal records at the valid journal end (v2).

        ``ops`` is the already-coalesced list when the caller (save()) has
        computed it for its size estimate; None coalesces here.

        Seeks to ``_journal_end`` — NOT raw EOF — and truncates first.  Any
        bytes past the last valid record are a crash-garbage tail; replay
        stops there forever, so appending after them would make every new
        record permanently unreachable on the next open.
        """
        if ops is None:
            ops = self._coalesce_pending_ops()
        self._check_still_ours()
        # Counted locally: a record written before ENOSPC/EIO is truncated
        # away and re-emitted by the retry, and counting it twice brought
        # the next full compaction forward (run 18 F-209).
        written = 0
        with open(self.path, "r+b") as f:
            f.seek(self._journal_end)
            f.truncate()
            for op in ops:
                body = b""
                if op["type"] == "write":
                    body = self._file_data.get(op["vpath"], b"")
                    # Sanity: a write op whose blob was later popped (by a
                    # delete on the same path) should have been coalesced
                    # away.  If we still see an empty body with chunk_count
                    # > 0, something slipped through — skip to avoid
                    # persisting a broken record.
                    if not body and op.get("chunk_count", 0) > 0:
                        continue
                body_offset = _write_journal_record(f, self.final_key, op, body)
                written += 1
                if op["type"] == "write" and op["vpath"] in self.dir_index:
                    entry = self.dir_index[op["vpath"]]
                    # Journal-region body offset is absolute; store relative
                    # to _data_offset so _get_blob() uses one formula.
                    entry["data_offset"] = body_offset - self._data_offset
                    entry["data_length"] = len(body)
            f.flush()
            os.fsync(f.fileno())
            self._file_size = f.tell()
            self._journal_end = self._file_size
        self._journal_records += written
        self._appended_since_open = True

        self._pending_ops.clear()
        self._file_data.clear()
        self._dirty = False
        # The journal now reflects dir_index exactly; refresh the snapshot
        # coalescing uses to decide tombstone emission.
        self._persisted_paths = set(self.dir_index)

    def compact(self) -> None:
        """Rewrite the entire container as a fresh baseline with no journal.

        Used automatically for v1→v2 upgrade and whenever the journal grows
        large relative to the baseline.  Also available to callers (e.g. a
        "Compact volume" action in the Volume Manager UI) to reclaim space
        that deleted / overwritten files leave in the journal.

        Preserves atomicity via ``.tmp`` + ``os.replace()`` — and the
        in-memory state mirrors that: ``dir_index`` / ``metadata`` / header
        fields are only committed after the replace succeeds.  A failed
        compact (disk full is the likely cause — pass 2 needs ~2× the
        container size) leaves both disk and memory exactly as before, so
        reads keep working and a retry is safe.  Mutating ``dir_index``
        offsets up front would poison a retry: it would copy the wrong byte
        ranges out of the intact original and *successfully* replace it
        with garbage.

        Memory profile is O(largest file in _file_data) plus a 1 MB sliding
        window for streaming unmodified blobs from the current container.
        """
        self._check_still_ours()
        # Pass 1: compute new offsets + lengths into FRESH entry dicts —
        # self.dir_index is not touched until the os.replace() commit point.
        # For modified files data_length comes from the pending blob; for
        # unmodified ones it was established at open() and is preserved.
        new_dir_index: dict[str, dict] = {}
        new_offset = 0
        for vpath in sorted(self.dir_index):
            entry = dict(self.dir_index[vpath])
            if entry.get("type") == "dir":
                new_dir_index[vpath] = entry
                continue
            if vpath in self._file_data:
                entry["data_length"] = len(self._file_data[vpath])
            entry["data_offset"] = new_offset
            new_offset += entry.get("data_length", 0)
            new_dir_index[vpath] = entry

        # Re-encrypt metadata and directory (cheap; ~KB of JSON).  The
        # format_version bump happens in the copy that gets encrypted, so
        # the persisted metadata agrees with the header immediately after a
        # v1→v2 upgrade — not one compact later.  A container already on
        # the journal layout keeps its version: nothing a compact writes
        # needs a newer reader, and an older build can then still open it.
        version = max(_JOURNAL_FORMAT_VERSION, self.header.get("version", 1))
        new_metadata = {**self.metadata, "format_version": version}
        meta_nonce, meta_ct = encrypt_metadata(self.final_key, new_metadata)
        dir_nonce, dir_ct = encrypt_directory(self.final_key, new_dir_index)

        # Pass 2: stream to a 0600 temp beside the container (a fixed
        # ``.tmp`` name opened with the umask made the first compaction
        # widen a 0600 container to 0644, and is a symlink target).  On
        # disk-full / I/O error the temp file is removed.
        # The target, not the name: rename(2) onto a symlink replaces the
        # link itself, leaving the real file — the one every other opener
        # uses — at its pre-compaction state (review run 19 F-201).
        target = os.path.realpath(self.path)
        fd, tmp_path = tempfile.mkstemp(
            prefix=f".{os.path.basename(target)}.qc-compact-",
            dir=os.path.dirname(target) or None,
        )
        os.close(fd)
        new_fd = -1
        _COPY_CHUNK = 1 << 20  # 1 MB sliding window for unmodified blobs
        try:
            with open(tmp_path, "wb") as tmp_f:
                write_header(tmp_f, self.header["volume_id"], meta_nonce, dir_nonce,
                             version=version)
                _write_auth_params(tmp_f, self.auth_params)
                _write_encrypted_block(tmp_f, meta_ct)
                _write_encrypted_block(tmp_f, dir_ct)
                new_data_offset = tmp_f.tell()

                # Open the current container read-only to copy unmodified
                # blobs.  os.replace() below atomically swaps it; any open
                # descriptor still refers to the old inode until it closes.
                with open(self.path, "rb") as src_f:
                    for vpath in sorted(new_dir_index):
                        entry = new_dir_index[vpath]
                        if entry.get("type") == "dir":
                            continue
                        length = entry.get("data_length", 0)
                        if length == 0:
                            continue
                        if vpath in self._file_data:
                            tmp_f.write(self._file_data[vpath])
                        else:
                            # Old offset still lives untouched in dir_index.
                            src_f.seek(
                                self._data_offset
                                + self.dir_index[vpath].get("data_offset", 0)
                            )
                            remaining = length
                            while remaining > 0:
                                chunk = src_f.read(min(remaining, _COPY_CHUNK))
                                if not chunk:
                                    raise ValueError(
                                        f"Volume file truncated while copying "
                                        f"unmodified blob for {vpath}"
                                    )
                                tmp_f.write(chunk)
                                remaining -= len(chunk)
                tmp_f.flush()
                os.fsync(tmp_f.fileno())
            # The replacement inherits the container's own permission bits
            # (a user may have loosened or tightened them since creation).
            try:
                os.chmod(tmp_path, stat.S_IMODE(os.stat(target).st_mode))
            except OSError:
                pass
            # Pin the new inode *before* the commit so identity is never
            # unpinned: a write between compact() and the next read used to
            # find _reader_fd None and skip the inode check (review run 20
            # F-001).  os.open on the temp follows the inode through rename.
            new_fd = os.open(tmp_path, os.O_RDONLY)
            # The commit point is inside the same guard: a replace refused
            # by a Finder-locked (uchg) container, or a folder that allows
            # mkstemp but not the rename, used to orphan a full-size copy.
            os.replace(tmp_path, target)
        except BaseException:
            if new_fd >= 0:
                try:
                    os.close(new_fd)
                except OSError:
                    pass
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        _fsync_dir(target)
        # Swap the pinned reader to the new inode; close the old one.  The
        # old inode is gone from the tree, but the descriptor kept it alive.
        with self._reader_lock:
            old_fd, self._reader_fd = self._reader_fd, new_fd
        if old_fd is not None:
            try:
                _os_close(old_fd)
            except OSError:
                pass
        self._appended_since_open = True

        # ── Commit point ──  The new container is on disk; only now do we
        # swap the in-memory state over to describe it.  _file_data is
        # cleared because all blobs now live canonically on disk at the new
        # offsets; future reads go through _get_blob() which will seek-read
        # them fresh.  The journal region is empty post-compact, so
        # _journal_start coincides with the end of the baseline blobs.
        self.dir_index = new_dir_index
        self.metadata = new_metadata
        self._data_offset = new_data_offset
        self._baseline_size = new_offset  # sum of lengths written above
        self._journal_start = new_data_offset + new_offset
        self._journal_end = self._journal_start
        # Re-stat to pick up the new file size for bounds checks.
        self._file_size = os.path.getsize(self.path)
        self.header["meta_nonce"] = meta_nonce
        self.header["dir_nonce"] = dir_nonce
        # Keep the header version in sync with what compact actually wrote
        # (v1 containers are upgraded to v2 on first save via this path).
        self.header["version"] = version
        self._journal_records = 0
        self._pending_ops.clear()
        self._file_data.clear()
        self._dirty = False
        self._persisted_paths = set(self.dir_index)

    def stat(self) -> dict:
        """Return volume statistics.

        Snapshots the index first: this is reached from the service's
        volume_list on a request worker that holds no FUSE lock, and the
        Volumes screen polls it every three seconds while FUSE workers add
        and remove keys — three live generator expressions over a mutating
        dict is a reliable "dictionary changed size during iteration".
        """
        entries = list(self.dir_index.values())
        file_count = sum(1 for e in entries if e.get("type") != "dir")
        dir_count = sum(1 for e in entries if e.get("type") == "dir")
        total_size = sum(
            e.get("size", 0) for e in entries if e.get("type") != "dir"
        )
        return {
            "file_count": file_count,
            "dir_count": dir_count,
            "total_plaintext_size": total_size,
            "container_size": os.path.getsize(self.path) if os.path.exists(self.path) else 0,
        }
