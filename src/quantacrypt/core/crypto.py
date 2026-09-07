"""QuantaCrypt Core Cryptography Module (512-bit streaming edition).

Key material is 512 bits throughout:
  - Argon2id produces a 64-byte key
  - the KEM shared secret (32 bytes) is HKDF-SHA-512 expanded to 64 bytes
  - XOR combination gives 64-byte final key material
  - SHA-512(final_key)[:32] used as AES-256-GCM key
  - Shamir over M521 (2^521 - 1), the largest Mersenne prime > 2^512

Chunked AES-GCM streaming — O(CHUNK_SIZE) RAM regardless of file size.

Format versions of the .qcx metadata envelope:
  1  Kyber-768 (round-3 CRYSTALS-Kyber); Argon2id parameters implied by the
     code; HMAC over the crypto fields only; whole-plaintext SHA-256 in the
     filename envelope.
  2  ML-KEM-768 (FIPS 203) named by the ``kem`` field; Argon2id parameters
     recorded in ``argon2`` so they can be raised later without stranding
     existing files; HMAC over every metadata field; no whole-plaintext
     hash (per-chunk AES-GCM with the index and last-chunk flag as AAD, plus
     the authenticated chunk count, already gives integrity, ordering and
     truncation detection — the hash cost 75% of encryption time on CPUs
     without SHA extensions and added nothing).
Files of both versions decrypt; new files are written as version 2.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import IO, Callable

import math
import shamirs
from argon2.exceptions import HashingError
from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.kyber import Kyber768
from kyber_py.ml_kem import ML_KEM_768

KEY_BYTES          = 64
ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 1   # single lane: full 64MB per hash path (see OWASP Argon2id guidance)
SHAMIR_PRIME       = (2 ** 521) - 1   # M521 Mersenne prime
FORMAT_VERSION     = 2
MIN_FORMAT_VERSION = 1   # files below this version are not supported
MAX_FORMAT_VERSION = 2   # files above this need a newer app
HKDF_INFO          = b"quantacrypt-v1-kem-expansion"
HMAC_INFO          = b"quantacrypt-v1-metadata-auth"
MAGIC              = b"QCBIN\x01"   # A2: single canonical definition, imported everywhere

# Which KEM a container names.  Format-1 .qcx and format-2 .qcv carry no
# ``kem`` field and were made with the round-3 Kyber class; everything newer
# says which one it used.  The two are NOT interchangeable: decapsulating a
# Kyber-768 ciphertext with ML-KEM-768 yields a different secret (the
# Fujisaki–Okamoto transform changed between the submission and FIPS 203).
KEM_KYBER768  = "Kyber768"
KEM_ML_KEM768 = "ML-KEM-768"
KEM_DEFAULT   = KEM_ML_KEM768
_KEMS = {KEM_KYBER768: Kyber768, KEM_ML_KEM768: ML_KEM_768}

# Bounds on Argon2id parameters a container may ask a reader to use.  They
# are read before anything is authenticated (the key they derive is what
# authenticates the rest), so a crafted file can name any values; the caps
# turn "allocate 64 GB and spin for an hour" into a bounded cost.  Floors
# stop a tampered file from silently downgrading the KDF — the HMAC would
# catch it anyway, but failing early names the real reason.
ARGON2_MIN_TIME_COST     = 1
ARGON2_MAX_TIME_COST     = 32
ARGON2_MIN_MEMORY_COST   = 8            # KiB — argon2's own minimum
ARGON2_MAX_MEMORY_COST   = 1 << 20      # 1 GiB
ARGON2_MIN_PARALLELISM   = 1
ARGON2_MAX_PARALLELISM   = 16
ARGON2_MIN_SALT_BYTES    = 8            # argon2's own minimum

#: Largest timestamp the name envelope is trusted with: 9999-12-31T23:59:59Z.
#: Beyond time_t, os.utime raised OverflowError after the plaintext was placed.
_MAX_TIMESTAMP = 253_402_300_800

# Streaming constants
# 4 MB plaintext chunks: large enough to amortise GCM overhead, small enough
# that RAM stays bounded (peak ≈ 2–3 × CHUNK_SIZE for read + encrypt + write buffers).
# Overhead: 8B header (seq + ct_len) + 16B GCM tag per chunk ≈ 0.0006% for 4 MB chunks.
CHUNK_SIZE     = 4 * 1024 * 1024          # 4 MB plaintext per chunk

__all__ = [
    # Constants
    "KEY_BYTES", "FORMAT_VERSION", "MIN_FORMAT_VERSION", "MAX_FORMAT_VERSION",
    "MAGIC", "CHUNK_SIZE", "SHAMIR_PRIME",
    "MNEMONIC_WORDS_PER_SHARE",
    "KEM_KYBER768", "KEM_ML_KEM768", "KEM_DEFAULT",
    # Key derivation
    "argon2id_derive", "argon2_params", "validate_argon2_params",
    "expand_kem_ss", "derive_aes_key",
    # Symmetric crypto
    "aes_gcm_encrypt", "aes_gcm_decrypt", "xor_bytes",
    # KEM
    "kyber_keygen", "kyber_encaps", "kyber_decaps", "validate_kem",
    # Shamir
    "shamir_split", "shamir_recover", "encode_share", "decode_share",
    # Streaming
    "ChunkEncryptor",
    "stream_encrypt_payload", "stream_decrypt_payload",
    "encrypt_single_streaming", "encrypt_shamir_streaming",
    "decrypt_streaming",
    # Mnemonic
    "share_to_mnemonic", "mnemonic_to_share",
]


def argon2id_derive(password: bytes, salt: bytes,
                    params: dict | None = None) -> bytes:
    """Argon2id over *password* with the shipped parameters, or with the
    (validated) parameters a format-2 container recorded."""
    _reject_empty_secret(password)
    if len(salt) < ARGON2_MIN_SALT_BYTES:
        # argon2 rejects it with HashingError — not a ValueError, so a crafted
        # file read as an app bug instead of as a bad file.
        raise ValueError("Argon2 salt is too short; the file may be corrupt")
    p = validate_argon2_params(params) if params else argon2_params()
    try:
        return hash_secret_raw(
            secret=password, salt=salt,
            time_cost=p["t"], memory_cost=p["m"],
            parallelism=p["p"], hash_len=KEY_BYTES, type=Type.ID,
        )
    except HashingError as exc:
        raise ValueError(f"Argon2 rejected the file's parameters ({exc}); "
                         "the file may be corrupt") from exc


def argon2_params() -> dict:
    """The parameters new containers record: ``{"t", "m", "p"}`` (time cost,
    memory cost in KiB, lanes) — read at call time so the test suite's
    cheaper values are what its own containers record."""
    return {"t": ARGON2_TIME_COST, "m": ARGON2_MEMORY_COST,
            "p": ARGON2_PARALLELISM}


def validate_argon2_params(params: object) -> dict:
    """Return ``params`` as a plain ``{"t","m","p"}`` dict or raise
    ``ValueError`` — see the bounds above for why every field is capped."""
    if not isinstance(params, dict):
        raise ValueError("Argon2 parameters are not an object; the file may be corrupt")
    out = {}
    for key, lo, hi in (("t", ARGON2_MIN_TIME_COST, ARGON2_MAX_TIME_COST),
                        ("m", ARGON2_MIN_MEMORY_COST, ARGON2_MAX_MEMORY_COST),
                        ("p", ARGON2_MIN_PARALLELISM, ARGON2_MAX_PARALLELISM)):
        v = params.get(key)
        if not isinstance(v, int) or isinstance(v, bool) or not (lo <= v <= hi):
            raise ValueError(
                f"Argon2 parameter {key!r} is out of range ({v!r}; expected "
                f"{lo}..{hi}). The file may be corrupt or from an unsupported version"
            )
        out[key] = v
    # argon2 itself needs 8 KiB per lane; a smaller value passes every
    # per-field bound and then raises from inside the library.
    if out["m"] < 8 * out["p"]:
        raise ValueError(
            f"Argon2 memory cost {out['m']} KiB is below 8 KiB per lane for "
            f"{out['p']} lanes. The file may be corrupt or from an unsupported version"
        )
    return out

def expand_kem_ss(kem_ss_raw: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA512(), length=KEY_BYTES,
                salt=None, info=HKDF_INFO).derive(kem_ss_raw)

def derive_aes_key(key_material: bytes) -> bytes:
    return hashlib.sha512(key_material).digest()[:32]

def aes_gcm_encrypt(key_material: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    ct    = AESGCM(derive_aes_key(key_material)).encrypt(nonce, plaintext, None)
    return nonce, ct

def aes_gcm_decrypt(key_material: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(derive_aes_key(key_material)).decrypt(nonce, ciphertext, None)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError(f"xor_bytes: length mismatch {len(a)} vs {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


#: Shortest password the core will encrypt with. The SwiftUI shell already
#: enforces this in its own validation; the Tk UI enforced nothing at all and
#: its batch path skipped even the soft "Weak password" warning, so the floor
#: belongs here, where both front ends pass through.
MIN_PASSWORD_LENGTH = 8


def reject_weak_secret(secret: bytes | str) -> None:
    """Refuse a password below MIN_PASSWORD_LENGTH.

    Argon2id at t=4/m=64 MiB buys roughly 20 bits against an offline
    attacker; it does not rescue a four-character password, and a .qcx is
    designed to be handed to someone else over an untrusted channel.
    """
    if isinstance(secret, str):
        secret = secret.encode()
    _reject_empty_secret(secret)
    if len(secret) < MIN_PASSWORD_LENGTH:
        # InvalidInput, not ValueError: classify_error maps a bare ValueError
        # to "format", the code meaning a damaged container. The service was
        # reporting a too-short password from volume_create as "format" and
        # the same condition from encrypt as "invalid_input".
        from quantacrypt.core.errors import InvalidInput
        raise InvalidInput(f"Use at least {MIN_PASSWORD_LENGTH} characters.")


def _reject_empty_secret(secret: bytes) -> None:
    """Defense in depth: the UI already blocks empty passwords, but refuse
    them in the crypto layer too so a regression can't quietly derive a
    trivially-bruteforceable key."""
    if not secret:
        raise ValueError(
            "Password / secret cannot be empty. Refusing to derive a "
            "trivially-guessable key"
        )

def _meta_hmac(key_material: bytes, meta_fields: dict) -> str:
    """Compute HMAC-SHA256 over a canonical encoding of authenticated metadata fields.
    Protects argon_salt, kyber_kem_ct, kyber_sk_enc_nonce, kyber_sk_enc, nonce
    against tampering. The tag is stored inside meta and verified before decryption."""
    # Canonical: sorted keys, deterministic JSON, prefixed with domain label
    canon = HMAC_INFO + json.dumps(meta_fields, sort_keys=True, separators=(",",":")).encode()
    tag   = hmac.new(key_material[:32], canon, hashlib.sha256).digest()
    return base64.b64encode(tag).decode()

#: Fields a format-1 HMAC never covered.  They are structural/display fields
#: that are present in meta at decryption time but were NOT in auth_fields
#: when the HMAC was computed.  "format_version" and "created_at" are
#: .qcv-only — excluding them is a no-op for .qcx metadata.  Format 2 covers
#: everything but the tag itself (review F-042: an unauthenticated ``mode``,
#: ``threshold`` or ``payload_offset`` could only ever cause a wrong-key
#: failure, but there was no reason to leave them out).
_HMAC_EXCLUDED_V1 = frozenset({
    "hmac", "version", "format_version", "created_at",
    "mode", "key_bits", "threshold", "total",
    "chunk_size", "payload_offset",
})


def _hmac_fields(meta: dict) -> dict:
    """The subset of *meta* the HMAC covers, by the envelope's own version."""
    version = meta.get("version", meta.get("format_version", 1))
    # .qcv metadata carries format_version 2 for the Kyber-era layout and 3+
    # for the ML-KEM one; .qcx carries version 1 or 2.  The wider HMAC
    # arrived with the ML-KEM bump in both, which "kem" marks unambiguously.
    # "format_version" stays out of the wide set too: compact() rewrites it
    # on a v1→v2 upgrade, and the .qcv copy sits inside the GCM-sealed
    # metadata block, which authenticates it regardless.
    if "kem" in meta or ("version" in meta and isinstance(version, int) and version >= 2):
        return {k: v for k, v in meta.items() if k not in ("hmac", "format_version")}
    return {k: v for k, v in meta.items() if k not in _HMAC_EXCLUDED_V1}


def _verify_meta_hmac(key_material: bytes, meta: dict) -> bool:
    """Verify metadata HMAC.
    Returns True if HMAC is present and valid.
    Raises ValueError if HMAC is absent or invalid (tampering detected)."""
    if "hmac" not in meta:
        # Every format-1 and format-2 writer stores it: absence is tampering,
        # and "unsupported version" here sent people to update the app.
        raise ValueError("Metadata HMAC is missing: the file may have been tampered with")
    stored   = meta["hmac"]
    if not isinstance(stored, str):
        raise ValueError("Metadata authentication failed: the file may have been tampered with")
    expected = _meta_hmac(key_material, _hmac_fields(meta))
    if not hmac.compare_digest(stored, expected):
        raise ValueError("Metadata authentication failed: the file may have been tampered with")
    return True


def validate_kem(name: object) -> str:
    """Return the KEM name a container may use, or raise ``ValueError``."""
    if name is None:
        return KEM_KYBER768
    if not isinstance(name, str) or name not in _KEMS:
        raise ValueError(
            f"Unsupported key encapsulation {name!r}. The file may be corrupt "
            "or from a newer version of QuantaCrypt"
        )
    return name


def kyber_keygen(kem: str = KEM_DEFAULT) -> tuple[bytes, bytes]:
    """Generate a keypair for *kem*: (public_key, secret_key)."""
    return _KEMS[validate_kem(kem)].keygen()

def kyber_encaps(pk: bytes, kem: str = KEM_DEFAULT) -> tuple[bytes, bytes]:
    kem_ss_raw, kem_ct = _KEMS[validate_kem(kem)].encaps(pk)
    return kem_ct, expand_kem_ss(kem_ss_raw)

def kyber_decaps(sk: bytes, kem_ct: bytes, kem: str = KEM_DEFAULT) -> bytes:
    """Decapsulate with the KEM the container names: callers pass
    ``validate_kem(meta.get("kem"))``, which maps an absent field (every
    container that predates it) to the legacy Kyber-768 class."""
    return expand_kem_ss(_KEMS[validate_kem(kem)].decaps(sk, kem_ct))


def shamir_split(secret_bytes: bytes, n: int, k: int) -> list[dict]:
    if not (2 <= k <= n <= 255):
        raise ValueError(
            f"Invalid Shamir parameters: need 2 <= k <= n <= 255 (got k={k}, n={n})"
        )
    secret_int = int.from_bytes(secret_bytes, "big")
    if secret_int >= SHAMIR_PRIME:
        raise ValueError(f"Secret ({len(secret_bytes)*8} bits) exceeds M521 prime, so it cannot be split safely")
    shares = shamirs.shares(secret_int, quantity=n, threshold=k, modulus=SHAMIR_PRIME)
    return [{"index": s.index, "value": s.value, "modulus": s.modulus,
             "threshold": k} for s in shares]

def shamir_recover(share_dicts: list[dict]) -> bytes:
    if not share_dicts:
        raise ValueError("Cannot recover from an empty share list")
    # Reject duplicate indices: entering the same share twice would leave the
    # effective quorum one share short, so the library would silently compute
    # the wrong secret.  Better to fail early with a clear message.
    indices = [s.get("index") for s in share_dicts]
    if len(set(indices)) != len(indices):
        raise ValueError(
            "Duplicate share detected. Each share must be unique. "
            "Check you haven't pasted the same share more than once."
        )
    # If every share carries a threshold, reject obviously-insufficient sets
    # before asking the library to do something undefined.  A stored threshold
    # is advisory: the library will still attempt recovery with fewer, but the
    # result would be garbage rather than an error.
    thresholds = {s.get("threshold") for s in share_dicts if "threshold" in s}
    if thresholds and all(t is not None for t in thresholds):
        min_threshold = min(thresholds)  # be lenient if shares disagree
        if len(share_dicts) < min_threshold:
            raise ValueError(
                f"Not enough shares to recover the secret "
                f"(have {len(share_dicts)}, need at least {min_threshold})"
            )
    objs       = [shamirs.shamirs.share(s["index"], s["value"], s["modulus"]) for s in share_dicts]
    secret_int = shamirs.recover(objs)
    if secret_int < 0 or secret_int >= (1 << (KEY_BYTES * 8)):
        raise ValueError(
            "Recovered secret is out of range: the shares may be corrupted or from a different file"
        )
    return secret_int.to_bytes(KEY_BYTES, "big")

def encode_share(share_dict: dict) -> str:
    return "QCSHARE-" + base64.b64encode(json.dumps(share_dict).encode()).decode()

def decode_share(share_str: str) -> dict:
    s = share_str.strip()
    # The callers route any case of the prefix here (package.py); a
    # lower-case one used to be refused as "not a share" after they had
    # already recognised it.
    if s[:8].upper() != "QCSHARE-":
        raise ValueError("Not a valid QuantaCrypt share")
    try:
        d = json.loads(base64.b64decode(s[8:]).decode())
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise ValueError("Share is malformed (could not decode)")
    if not isinstance(d, dict):
        raise ValueError("Share is malformed (could not decode)")
    # Validate required fields and types
    for field in ("index", "value", "modulus"):
        if field not in d:
            raise ValueError(f"Share missing required field: {field!r}")
        if not isinstance(d[field], int) or isinstance(d[field], bool):
            raise ValueError(f"Share field {field!r} must be an integer, got {type(d[field]).__name__}")
    # Validate modulus matches the known prime — reject any crafted/downgraded modulus
    if d["modulus"] != SHAMIR_PRIME:
        raise ValueError(
            f"Share modulus does not match expected M521 prime "
            f"(got {d['modulus']}, expected {SHAMIR_PRIME}). "
            "This share may be from a different version or have been tampered with."
        )
    # Validate index and value are in sensible ranges
    if not (1 <= d["index"] <= 255):
        raise ValueError(f"Share index out of range: {d['index']}")
    if not (0 < d["value"] < SHAMIR_PRIME):
        raise ValueError(f"Share value out of range")
    # threshold is advisory but shamir_recover compares it with an int; a
    # string here reached the service as a TypeError ("app bug").
    if "threshold" in d:
        t = d["threshold"]
        if not isinstance(t, int) or isinstance(t, bool) or not (0 <= t <= 255):
            raise ValueError(f"Share threshold is not a valid count: {t!r}")
    return d




# ── v1 Streaming Payload: chunked AES-GCM ────────────────────────────────────
# Security properties:
#   • Each chunk is an independent AES-GCM AEAD unit — O(CHUNK_SIZE) RAM.
#   • Nonce per chunk = base_nonce XOR chunk_index (12-byte big-endian).
#     base_nonce is random per file, so cross-file nonce reuse is impossible.
#   • AAD per chunk = chunk_index (8-byte big-endian) + last-chunk flag byte.
#     Prevents chunk reordering (wrong index → bad tag) and truncation (last
#     chunk must have flag=0xFF; earlier chunks flag=0x00).
#   • chunk_count in metadata + HMAC gives a second truncation guard.
#   • On-disk layout: [uint32_be(ct_len)][ciphertext+tag] repeated, then metadata.


class CancelledOperation(Exception):
    """Raised from inside stream_encrypt/decrypt when cancel_check returns True.

    The UI passes a callable that reads a threading.Event; when the user
    hits Cancel, the next chunk boundary raises this exception and callers
    clean up (delete the partial output).
    """


def _chunk_nonce(base_nonce: bytes, chunk_idx: int) -> bytes:
    return (int.from_bytes(base_nonce, "big") ^ chunk_idx).to_bytes(12, "big")

def _chunk_aad(chunk_idx: int, is_last: bool) -> bytes:
    return chunk_idx.to_bytes(8, "big") + (b"\xff" if is_last else b"\x00")


class ChunkEncryptor:
    """Push-model chunk encryptor: ``write()`` plaintext in any piece sizes,
    ``finish()`` once, and the same ``[seq][ct_len][ct+tag]`` stream that
    :func:`stream_encrypt_payload` produces lands in *dst_file*.

    A chunk is only sealed once the *next* one has started (the buffer holds
    more than CHUNK_SIZE bytes), which is how the last-chunk flag in the AAD
    is known without seeing the source's size up front.  That makes the
    object usable as the ``fileobj`` of a ``zipfile.ZipFile`` — it has no
    ``seek``/``tell``, so zipfile writes data descriptors — which is what
    lets folders be archived straight into the cipher with no plaintext
    staging file on disk.
    """

    def __init__(self, dst_file: IO[bytes], final_key: bytes, *,
                 hash_plaintext: bool = False,
                 cancel_check: Callable[[], bool] | None = None):
        self._dst = dst_file
        self._cipher = AESGCM(derive_aes_key(final_key))
        self._cancel = cancel_check
        self._buf = bytearray()
        self._hash = hashlib.sha256() if hash_plaintext else None
        self._finished = False
        self.base_nonce = secrets.token_bytes(12)
        self.chunk_count = 0
        self.bytes_written = 0
        self.plain_bytes = 0

    # ── file-like surface (what zipfile needs) ──
    def write(self, data) -> int:
        if self._finished:
            raise ValueError("write() after finish()")
        n = len(data)
        self._buf += data
        while len(self._buf) > CHUNK_SIZE:
            # Seal straight out of the buffer (no bytes() copy).  Every view
            # must be released before the bytearray can be resized.
            mv = memoryview(self._buf)
            head = mv[:CHUNK_SIZE]
            try:
                self._seal(head, is_last=False)
            finally:
                head.release()
                mv.release()
            del self._buf[:CHUNK_SIZE]
        return n

    def flush(self) -> None:
        """No-op: chunks are sealed by size, never by a caller's flush."""

    def seekable(self) -> bool:
        return False

    # ── the chunk stream ──
    def seal_chunk(self, chunk, is_last: bool) -> None:
        """Encrypt one whole chunk from the caller's own buffer.  A reader
        that already has the data in CHUNK_SIZE pieces (a file) uses this
        directly and skips the write() buffer and its copies.  Not to be
        mixed with write(): the buffer must be empty."""
        if self._finished:
            raise ValueError("seal_chunk() after finish()")
        if self._buf:
            raise ValueError("seal_chunk() with buffered write() data pending")
        self._seal(chunk, is_last)

    def _seal(self, chunk, is_last: bool) -> None:
        if self._cancel and self._cancel():
            raise CancelledOperation("Encryption cancelled")
        if self._hash is not None:
            self._hash.update(chunk)
        nonce = _chunk_nonce(self.base_nonce, self.chunk_count)
        aad   = _chunk_aad(self.chunk_count, is_last)
        ct    = self._cipher.encrypt(nonce, chunk, aad)    # len = len(chunk) + 16
        self._dst.write(self.chunk_count.to_bytes(4, "big"))
        self._dst.write(len(ct).to_bytes(4, "big"))
        self._dst.write(ct)
        self.bytes_written += 8 + len(ct)
        self.plain_bytes += len(chunk)
        self.chunk_count += 1

    def finish(self) -> str | None:
        """Seal the final chunk (a 0-byte source seals none).  Returns the
        plaintext SHA-256 hex digest when hashing was requested, else None."""
        if self._finished:
            raise ValueError("finish() called twice")
        if self._buf:
            residue, self._buf = bytes(self._buf), bytearray()
            self._seal(residue, is_last=True)
        self._finished = True
        return self._hash.hexdigest() if self._hash is not None else None


def stream_encrypt_payload(
    src_path: str,
    dst_file: IO[bytes],
    final_key: bytes,
    payload_size: int,
    progress_cb: Callable[[str], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
    hash_plaintext: bool = True,
) -> tuple[bytes, int, int, str | None]:
    """
    Stream-encrypt src_path into dst_file using chunked AES-GCM.
    Writes [uint32_be(seq)][uint32_be(ct_len)][ct+tag] for each chunk.
    Returns (base_nonce, chunk_count, bytes_written, plaintext_sha256_hex);
    the hash is None when *hash_plaintext* is False (format 2 does not
    store one).  dst_file must already be open and positioned correctly.

    If *cancel_check* is given and returns True at a chunk boundary, the
    function raises :class:`CancelledOperation` so the caller can clean up
    the partial output before re-raising or swallowing.
    """
    enc = ChunkEncryptor(dst_file, final_key, hash_plaintext=hash_plaintext,
                         cancel_check=cancel_check)
    last_report = 0.0
    with open(src_path, "rb") as src:
        # Read ahead by one chunk to know when we're at the last one, and
        # seal each chunk from the read buffer itself — no intermediate copy.
        buf = src.read(CHUNK_SIZE)
        while buf:
            nxt = src.read(CHUNK_SIZE)
            enc.seal_chunk(buf, is_last=not nxt)
            if progress_cb and payload_size:
                pct = min(enc.plain_bytes, payload_size) / payload_size
                if pct - last_report >= 0.01:
                    progress_cb(f"Encrypting payload (AES-256-GCM, 512-bit key material)... {int(pct*100)}%")
                    last_report = pct
            buf = nxt
    digest = enc.finish()
    return enc.base_nonce, enc.chunk_count, enc.bytes_written, digest

def stream_decrypt_payload(
    src_path: str,
    dst_file: IO[bytes],
    final_key: bytes,
    payload_offset: int,
    chunk_count: int,
    base_nonce: bytes,
    progress_cb: Callable[[str], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
    hash_plaintext: bool = True,
) -> str | None:
    """
    Stream-decrypt chunked payload from src_path (starting at payload_offset)
    into dst_file.  Raises ValueError on any authentication failure.
    Returns the SHA-256 hex digest of the decrypted plaintext, computed
    incrementally during decryption, or None when *hash_plaintext* is False.
    """
    aes_key = derive_aes_key(final_key)
    cipher  = AESGCM(aes_key)
    content_hash = hashlib.sha256() if hash_plaintext else None
    last_report = 0.0

    with open(src_path, "rb") as src:
        src.seek(payload_offset)
        for i in range(chunk_count):
            if cancel_check and cancel_check():
                raise CancelledOperation("Decryption cancelled")
            is_last  = (i == chunk_count - 1)
            seq_raw  = src.read(4)
            if len(seq_raw) < 4:
                raise ValueError("File appears truncated: the payload is incomplete")
            seq = int.from_bytes(seq_raw, "big")
            if seq != i:
                raise ValueError(f"Chunk sequence mismatch at position {i} (got {seq})")
            ct_len_raw = src.read(4)
            if len(ct_len_raw) < 4:
                raise ValueError("File appears truncated: the chunk header is incomplete")
            ct_len = int.from_bytes(ct_len_raw, "big")
            # The length field is attacker-controlled and unauthenticated
            # at this point: bound it before allocating, or a crafted
            # header requests a 4 GB read ahead of any GCM tag check.
            if ct_len > CHUNK_SIZE + 16:
                raise ValueError(
                    f"Chunk {i} declares an implausible size ({ct_len} "
                    f"bytes). The file may be corrupt"
                )
            ct     = src.read(ct_len)
            if len(ct) < ct_len:
                raise ValueError("File appears truncated: the chunk data is incomplete")
            nonce = _chunk_nonce(base_nonce, i)
            aad   = _chunk_aad(i, is_last)
            try:
                plain = cipher.decrypt(nonce, ct, aad)
            except (ValueError, InvalidTag):
                raise ValueError(
                    f"Authentication failed on chunk {i}: "
                    "the file may be corrupt or the wrong key was used"
                )
            if content_hash is not None:
                content_hash.update(plain)
            dst_file.write(plain)
            # Throttle progress callbacks to ~1% intervals to avoid
            # flooding the Tk event queue on large files (especially
            # volume files decrypted at 64 KB granularity).
            if progress_cb and chunk_count:
                pct = (i + 1) / chunk_count
                if pct - last_report >= 0.01 or i + 1 == chunk_count:
                    progress_cb(f"Decrypting payload (AES-256-GCM)... {int(pct*100)}%")
                    last_report = pct

    return content_hash.hexdigest() if content_hash is not None else None




# ── v1 Streaming API ──────────────────────────────────────────────────────────
# These functions write/read the chunked payload from disk and return/accept
# the metadata dict.  The caller (encryptor.py / decryptor.py) handles the
# outer file assembly (magic + meta JSON at tail).

#: A plaintext source: a path, or a producer that writes the plaintext into
#: the sink it is handed (``zip_folder`` archiving straight into the cipher).
Source = "str | Callable[[IO[bytes]], None]"


def _payload_offset(dst_file: IO[bytes]) -> int:
    """Where the payload starts in *dst_file* — recorded in the metadata and
    covered by the format-2 HMAC.  A sink with no position reports 0."""
    try:
        return dst_file.tell()
    except (AttributeError, OSError, ValueError):
        return 0


def _encrypt_source(src, dst_file: IO[bytes], final_key: bytes,
                    progress_cb, cancel_check) -> tuple[bytes, int, int]:
    """Encrypt *src* (path or producer) into dst_file.
    Returns (base_nonce, chunk_count, plaintext_bytes)."""
    if callable(src):
        enc = ChunkEncryptor(dst_file, final_key, cancel_check=cancel_check)
        src(enc)
        enc.finish()
        return enc.base_nonce, enc.chunk_count, enc.plain_bytes
    payload_size = os.path.getsize(src)
    base_nonce, chunk_count, _, _ = stream_encrypt_payload(
        src, dst_file, final_key, payload_size, progress_cb,
        cancel_check=cancel_check, hash_plaintext=False)
    return base_nonce, chunk_count, payload_size


def encrypt_single_streaming(
    src_path,
    dst_file: IO[bytes],
    password: str,
    filename: str = "",
    progress_cb: Callable[[str], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> dict:
    """
    Stream-encrypt *src_path* — a path, or a producer callable that writes
    the plaintext into the sink it is given — into dst_file (already open,
    positioned after any embedded binary).  Returns the metadata dict (to
    be written as tail).  RAM usage: O(CHUNK_SIZE), not O(file_size).
    """
    def _p(m): progress_cb and progress_cb(m)
    payload_offset = _payload_offset(dst_file)
    _p("Deriving 512-bit password key (Argon2id)...")
    argon_salt = secrets.token_bytes(32)
    argon2 = argon2_params()
    # Encode + drop the str reference so it's not a named local for the
    # remainder of this (slow) function.  Doesn't zero the heap, but
    # shortens the window a heap dump would have to catch.
    pw_bytes = password.encode()
    password = None  # noqa: F841
    argon_key  = argon2id_derive(pw_bytes, argon_salt, argon2)
    del pw_bytes
    _p("Generating ML-KEM-768 keypair...")
    pk, sk = kyber_keygen(KEM_DEFAULT)
    _p("Encapsulating + HKDF-SHA-512 expanding to 512 bits...")
    kem_ct, kem_ss = kyber_encaps(pk, KEM_DEFAULT)
    final_key = xor_bytes(argon_key, kem_ss)
    _p("Encrypting KEM private key...")
    sk_nonce, sk_ct = aes_gcm_encrypt(argon_key, sk)

    _p("Encrypting payload (AES-256-GCM, 512-bit key material)...")
    base_nonce, chunk_count, plain_bytes = _encrypt_source(
        src_path, dst_file, final_key, progress_cb, cancel_check)

    # Encrypt filename + size + timestamp separately (tiny, in-memory) so
    # they are confidential and authenticated.
    fname_plain = json.dumps({"n": filename, "sz": plain_bytes,
                               "ts": int(time.time())},
                              separators=(",", ":")).encode()
    fname_nonce, fname_ct = aes_gcm_encrypt(final_key, fname_plain)

    def b64(b): return base64.b64encode(b).decode()
    auth_fields = {
        "argon_salt":          b64(argon_salt),
        "kyber_kem_ct":        b64(kem_ct),
        "kyber_sk_enc_nonce":  b64(sk_nonce),
        "kyber_sk_enc":        b64(sk_ct),
        "payload_nonce":       b64(base_nonce),
        "payload_chunk_count": chunk_count,
        "filename_nonce":      b64(fname_nonce),
        "filename_enc":        b64(fname_ct),
    }
    meta = {"version": FORMAT_VERSION, "mode": "single", "key_bits": 512,
            "chunk_size": CHUNK_SIZE, "kem": KEM_DEFAULT, "argon2": argon2,
            "payload_offset": payload_offset, **auth_fields}
    meta["hmac"] = _meta_hmac(final_key, _hmac_fields(meta))
    return meta


def encrypt_shamir_streaming(
    src_path,
    dst_file: IO[bytes],
    n: int,
    k: int,
    filename: str = "",
    progress_cb: Callable[[str], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> tuple[dict, list[str]]:
    """
    Stream-encrypt *src_path* (path or producer, as encrypt_single_streaming)
    into dst_file using Shamir key split.  Returns (meta_dict, share_strings).
    """
    def _p(m): progress_cb and progress_cb(m)
    payload_offset = _payload_offset(dst_file)
    _p("Generating 512-bit random master key...")
    master_key = secrets.token_bytes(KEY_BYTES)
    _p("Generating ML-KEM-768 keypair...")
    pk, sk = kyber_keygen(KEM_DEFAULT)
    _p("Encapsulating + HKDF-SHA-512 expanding to 512 bits...")
    kem_ct, kem_ss = kyber_encaps(pk, KEM_DEFAULT)
    final_key = xor_bytes(master_key, kem_ss)
    _p("Encrypting KEM private key under master key...")
    sk_nonce, sk_ct = aes_gcm_encrypt(master_key, sk)

    _p("Encrypting payload (AES-256-GCM, 512-bit key material)...")
    base_nonce, chunk_count, plain_bytes = _encrypt_source(
        src_path, dst_file, final_key, progress_cb, cancel_check)

    fname_plain = json.dumps({"n": filename, "sz": plain_bytes,
                               "ts": int(time.time())},
                              separators=(",", ":")).encode()
    fname_nonce, fname_ct = aes_gcm_encrypt(final_key, fname_plain)

    _p(f"Splitting 512-bit key into {n} shares over M521 (threshold {k})...")
    raw_shares    = shamir_split(master_key, n, k)
    share_strings = [encode_share(s) for s in raw_shares]

    def b64(b): return base64.b64encode(b).decode()
    auth_fields = {
        "kyber_kem_ct":        b64(kem_ct),
        "kyber_sk_enc_nonce":  b64(sk_nonce),
        "kyber_sk_enc":        b64(sk_ct),
        "payload_nonce":       b64(base_nonce),
        "payload_chunk_count": chunk_count,
        "filename_nonce":      b64(fname_nonce),
        "filename_enc":        b64(fname_ct),
    }
    meta = {"version": FORMAT_VERSION, "mode": "shamir", "key_bits": 512,
            "threshold": k, "total": n, "chunk_size": CHUNK_SIZE,
            "kem": KEM_DEFAULT, "payload_offset": payload_offset, **auth_fields}
    meta["hmac"] = _meta_hmac(master_key, _hmac_fields(meta))
    return meta, share_strings


def decrypt_streaming(
    src_path: str,
    dst_file: IO[bytes],
    meta: dict,
    final_key: bytes,
    progress_cb: Callable[[str], None] | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> tuple[str, int, int]:
    """
    Stream-decrypt chunked payload from src_path into dst_file.
    payload_offset is read from meta (set by the encryptor to skip any embedded binary).
    Returns (filename, sz, ts) where filename is the original filename, sz is the
    original file size in bytes, and ts is the Unix timestamp of encryption.
    """
    def _p(m): progress_cb and progress_cb(m)
    def d64(k): return base64.b64decode(meta[k])

    payload_offset = meta.get("payload_offset", 0)
    chunk_count    = meta["payload_chunk_count"]
    base_nonce     = d64("payload_nonce")

    # The envelope first: it is independent of the payload, and whether it
    # carries a whole-plaintext hash (format 1) decides whether the payload
    # pass has to compute one.
    fname_plain = aes_gcm_decrypt(final_key, d64("filename_nonce"), d64("filename_enc"))
    inner = json.loads(fname_plain)
    if not isinstance(inner, dict):
        raise ValueError("The file's name envelope is not valid; the file may be corrupt")
    expected_sha256 = inner.get("sha256")

    _p("Decrypting payload (AES-256-GCM)...")
    decrypted_sha256 = stream_decrypt_payload(
        src_path, dst_file, final_key,
        payload_offset, chunk_count, base_nonce, progress_cb,
        cancel_check=cancel_check, hash_plaintext=bool(expected_sha256))

    # Format 1 recorded a whole-plaintext SHA-256; compare it.  Format 2 does
    # not: per-chunk GCM with the index and last flag as AAD, plus the
    # authenticated chunk count, already proves every byte, its order and
    # the length.
    if expected_sha256 and decrypted_sha256 != expected_sha256:
        raise ValueError(
            "Content integrity check failed. The decrypted output does not match "
            "the original file. The file may have been corrupted."
        )

    # The envelope is GCM-sealed, so only the encryptor controls it — but a
    # .qcx is made to be handed to you, and a non-string name or a timestamp
    # beyond time_t raised after the plaintext was already placed.
    name, size, ts = inner.get("n", ""), inner.get("sz", 0), inner.get("ts", 0)
    if not isinstance(name, str):
        name = ""
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        size = 0
    if (not isinstance(ts, (int, float)) or isinstance(ts, bool)
            or not (0 <= ts < _MAX_TIMESTAMP)):
        ts = 0
    return name, size, ts


# ── Mnemonic Encoding (BIP-39 wordlist, 50 words per share) ───────────────────
# Layout (545 bits total → 50 × 11-bit words):
#   [521 bits: value] [8 bits: index] [8 bits: threshold] [8 bits: SHA-256 checksum]
# 50 words carry 550 bits for a 545-bit payload: the first word's top five
# bits are padding, so it is always one of the first 64 words and the
# decoder rejects any other (the checksum alone cannot see those bits).
# The M521 modulus is a constant and never stored in the share.

_INDEX_BITS     = 8
_THRESHOLD_BITS = 8
_VALUE_BITS     = 521
_CHECKSUM_BITS  = 8
_TOTAL_BITS     = _INDEX_BITS + _THRESHOLD_BITS + _VALUE_BITS + _CHECKSUM_BITS  # 545
_NUM_WORDS      = math.ceil(_TOTAL_BITS / 11)  # 50

_WORDLIST_CACHE = None
_WORDLIST_INDEX: dict[str, int] | None = None
def _load_wordlist():
    global _WORDLIST_CACHE
    if _WORDLIST_CACHE is None:
        from mnemonic import Mnemonic
        _WORDLIST_CACHE = Mnemonic('english').wordlist
    return _WORDLIST_CACHE

def _wordlist_index() -> dict[str, int]:
    """word → position, so decoding is a hash lookup rather than a linear
    scan whose duration depends on the (secret) word."""
    global _WORDLIST_INDEX
    if _WORDLIST_INDEX is None:
        _WORDLIST_INDEX = {w: i for i, w in enumerate(_load_wordlist())}
    return _WORDLIST_INDEX

def _int_to_words(n: int, bit_length: int, wordlist: list) -> list:
    num_words = math.ceil(bit_length / 11)
    result = []
    remaining = num_words * 11
    for _ in range(num_words):
        remaining -= 11
        result.append(wordlist[(n >> remaining) & 0x7FF])
    return result

def share_to_mnemonic(share_dict: dict) -> str:
    """
    Encode a share dict into a 50-word mnemonic phrase.
    All data (index, threshold, value) is packed with an 8-bit SHA-256 checksum.
    The M521 modulus is not stored — it's a constant recovered at decode time.

    Bit layout:
      [5 bits: zero padding] [521 bits: value] [8 bits: index]
      [8 bits: threshold] [8 bits: checksum]
    The padding sits in the first word, which therefore always comes from
    the first 64 words of the BIP-39 list; mnemonic_to_share rejects a
    first word outside that range so a typo there is caught like any other.
    """
    wordlist  = _load_wordlist()
    index     = share_dict["index"]
    threshold = share_dict.get("threshold", 0)  # optional, stored for self-containment
    value     = share_dict["value"]

    # Pack bits: value in HIGH bits, then index, then threshold
    # Layout: value(521) | index(8) | threshold(8)
    data_bits  = _VALUE_BITS + _INDEX_BITS + _THRESHOLD_BITS  # 537
    packed     = (value << (_INDEX_BITS + _THRESHOLD_BITS)) | (index << _THRESHOLD_BITS) | threshold
    packed_len = math.ceil(data_bits / 8)
    packed_bytes = packed.to_bytes(packed_len, "big")

    # 8-bit checksum
    checksum   = hashlib.sha256(packed_bytes).digest()[0]
    full_int   = (packed << _CHECKSUM_BITS) | checksum

    words = _int_to_words(full_int, _TOTAL_BITS, wordlist)
    if len(words) != _NUM_WORDS:
        raise ValueError(f"Internal error: generated {len(words)} words, expected {_NUM_WORDS}")
    return " ".join(words)


def mnemonic_to_share(mnemonic: str) -> dict:
    """
    Decode a 50-word mnemonic back into a share dict.
    Raises ValueError on bad word or checksum mismatch.
    """
    wordlist = _load_wordlist()
    words    = mnemonic.strip().split()

    if len(words) != _NUM_WORDS:
        raise ValueError(f"Expected {_NUM_WORDS} words, got {len(words)}")

    # Check all words are valid (hash lookups: a linear scan's duration
    # depends on the secret word).
    index = _wordlist_index()
    bad = [w for w in words if w.lower() not in index]
    if bad:
        raise ValueError(f"Unknown word(s): {', '.join(bad)}")

    raw = 0
    for w in words:
        raw = (raw << 11) | index[w.lower()]
    # The five padding bits above the payload must be zero.  Masking them
    # off silently accepted 31 other first words as the same share — the
    # one transcription error the checksum could not see.
    if raw >> _TOTAL_BITS:
        raise ValueError(
            "Checksum mismatch: the first word is not one a share can start "
            "with. The share may have a typo or been corrupted"
        )
    full_int = raw & ((1 << _TOTAL_BITS) - 1)

    checksum        = full_int & 0xFF
    packed          = full_int >> _CHECKSUM_BITS
    data_bits       = _VALUE_BITS + _INDEX_BITS + _THRESHOLD_BITS
    packed_bytes    = packed.to_bytes(math.ceil(data_bits / 8), "big")
    expected_cs     = hashlib.sha256(packed_bytes).digest()[0]

    if checksum != expected_cs:
        raise ValueError(
            f"Checksum mismatch (got {checksum:#04x}, expected {expected_cs:#04x}). "
            "The share may have a typo or been corrupted"
        )

    # Unpack: value in high bits, then index, then threshold
    threshold = packed & 0xFF
    index     = (packed >> _THRESHOLD_BITS) & 0xFF
    value     = packed >> (_INDEX_BITS + _THRESHOLD_BITS)

    # Same ranges decode_share enforces: a share at x=0 would BE the secret,
    # and a value at or above the modulus is not a field element.
    if not (1 <= index <= 255):
        raise ValueError(f"Share index out of range: {index}")
    if not (0 < value < SHAMIR_PRIME):
        raise ValueError("Share value out of range")

    return {
        "index":     index,
        "value":     value,
        "modulus":   SHAMIR_PRIME,
        "threshold": threshold,
    }


MNEMONIC_WORDS_PER_SHARE = _NUM_WORDS  # 50
